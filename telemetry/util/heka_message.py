#!/usr/bin/env python
# encoding: utf-8

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import message_pb2  # generated from https://github.com/mozilla-services/heka (message/message.proto)
import boto
import snappy
import struct
import gzip

from cStringIO import StringIO
from google.protobuf.message import DecodeError


RECORD_SEPARATOR = 0x1e


class BacktrackableFile:
    """
    Wrapper for file-like objects that exposes a file-like object interface,
    but also allows backtracking to just after the first byte in the file-like
    object equal to `RECORD_SEPARATOR` that we haven't backtracked to yet.

    This is useful for parsing Heka records, since backtracking will always move us
    back to the start of a possible Heka record.

    See http://hekad.readthedocs.org/en/latest/message/ for Heka message details.
    """
    def __init__(self, stream):
        self._stream = stream
        self._buffer = StringIO()
        self._position = 0

    def tell(self):
        """
        Returns the virtual position within this file-like object;
        the effective offset from the beginning of the wrapped file-like object.
        """
        return self._position

    def read(self, size):
        """
        Read and return `size` bytes. Might not actually read the wrapped
        file-like object if there are enough bytes buffered.
        """
        buffer_data = self._buffer.read(size)
        to_read = size - len(buffer_data)

        assert to_read >= 0, "Read data must be equal or smaller to requested data"
        if to_read == 0:
            return buffer_data

        stream_data = self._stream.read(to_read)
        self._buffer.write(stream_data)
        result = buffer_data + stream_data
        self._position += len(result)

        return result

    def close(self):
        """Close the file-like object, as well as its wrapped file-like object."""
        self._buffer.close()
        if type(self._stream) == boto.s3.key.Key:
            if self._stream.resp:  # Hack! Connections are kept around otherwise!
                self._stream.resp.close()

            self._stream.close(True)
        else:
            self._stream.close()

    def backtrack(self):
        """
        Move the file cursor back to just after the first `RECORD_SEPARATOR` byte
        in the stream that we haven't already backtracked to. If none, 
        """
        buffer = self._buffer.getvalue()

        # start searching after the first byte, since the first byte would often be a record separator,
        # and we don't want to backtrack to the same place every time
        index = buffer.find(chr(RECORD_SEPARATOR), 1)
        if index == -1:
            # no record separator found, but we don't want to potentially backtrack to our original place,
            # which would cause an infinite loop if the last record is malformed;
            # we'll just not do anything instead
            self._buffer = StringIO()
            return

        # update the position to account for moving backward in the stream
        self._position += index + 1 - len(buffer)

        # reset the buffer, since we'll never want to backtrack before this point ever again
        # basically we're going to discard everything before this backtracking operation
        self._buffer = StringIO()

        # we add 1 because we want to have the same behaviour as `read_until_next`,
        # which will set the cursor to just after the record separator
        self._buffer.write(buffer[index + 1:])
        self._buffer.seek(0)


class UnpackedRecord():
    """Represents a single Heka message. See http://hekad.readthedocs.org/en/latest/message/ for details."""
    def __init__(self, raw, header, message=None, error=None):
        self.raw = raw
        self.header = header
        self.message = message
        self.error = error


# Returns (bytes_skipped=int, eof_reached=bool)
def read_until_next(fin, separator=RECORD_SEPARATOR):
    """
    Read bytes in a file-like object until `separator` is found.

    Returns the number of bytes skipped, and whether the search failed to find `separator`. If `separator` is found,
    the number of bytes skipped is one less than the actual number of bytes successfully read. Otherwise, they are the same.

    Note that when this completes, the file cursor will be immediately after the `separator` byte,
    so the next byte read will be the one after it.
    """
    bytes_skipped = 0
    while True:
        c = fin.read(1)
        if c == '':
            return (bytes_skipped, True)
        elif ord(c) != separator:
            bytes_skipped += 1
        else:
            break
    return (bytes_skipped, False)


# Stream Framing:
#  https://hekad.readthedocs.org/en/latest/message/index.html
def read_one_record(input_stream, raw=False, verbose=False, strict=False, try_snappy=True):
    """
    Attempt to read one Heka record from the file-like object `input_stream`, returning an `UnpackedRecord` instance.

    Returns the record (or `None` if the stream ended while reading), and the total number of bytes read.

    If and only if `raw` is set, messages won't be parsed (the `UnpackedRecord` instance still contains the raw record, however).

    If and only if `verbose` is set, useful debugging information will be printed while parsing.

    If and only if `strict` is set, the stream is validated more thoroughly.

    If and only if `try_snappy` is set, the function will also attempt to decompress the message body with Snappy.
    """
    # Read 1 byte record separator (and keep reading until we get one)
    total_bytes = 0
    skipped, eof = read_until_next(input_stream, RECORD_SEPARATOR)
    total_bytes += skipped
    if eof:
        return None, total_bytes
    else:
        # we've read one separator (plus anything we skipped)
        total_bytes += 1

    if skipped > 0:
        if strict:
            raise ValueError("Unexpected character(s) at the start of record")
        if verbose:
            print "Skipped", skipped, "bytes to find a valid separator"

    #print "position", input_stream.tell()
    raw_record = struct.pack("<B", 0x1e)

    # Read the header length
    header_length_raw = input_stream.read(1)
    if header_length_raw == '': # no more data to read
        return None, total_bytes

    total_bytes += 1
    raw_record += header_length_raw

    # The "<" is to force it to read as Little-endian to match the way it's
    # written. This is the "native" way in linux too, but might as well make
    # sure we read it back the same way.
    (header_length,) = struct.unpack('<B', header_length_raw)

    header_raw = input_stream.read(header_length)
    if header_length > 0 and header_raw == '': # no more data to read
        return None, total_bytes
    total_bytes += header_length
    raw_record += header_raw

    header = message_pb2.Header()
    header.ParseFromString(header_raw)
    unit_separator = input_stream.read(1)
    total_bytes += 1
    if ord(unit_separator[0]) != 0x1f:
        raise DecodeError("Unexpected unit separator character in record at offset {}: {}".format(total_bytes, ord(unit_separator[0])))
    raw_record += unit_separator

    #print "message length:", header.message_length
    message_raw = input_stream.read(header.message_length)

    total_bytes += header.message_length
    raw_record += message_raw

    message = None
    if not raw:
        message = message_pb2.Message()
        parsed_ok = False
        if try_snappy:
            try:
                message.ParseFromString(snappy.decompress(message_raw))
                parsed_ok = True
            except:
                # Wasn't snappy-compressed
                pass
        if not parsed_ok:
            # Either we didn't want to attempt snappy, or the
            # data was not snappy-encoded (or it was just bad).
            message.ParseFromString(message_raw)

    return UnpackedRecord(raw_record, header, message), total_bytes


def unpack_file(filename, **kwargs):
    fin = None
    if filename.endswith(".gz"):
        fin = gzip.open(filename, "rb")
    else:
        fin = open(filename, "rb")
    return unpack(fin, **kwargs)


def unpack_string(string, **kwargs):
    return unpack(StringIO(string), **kwargs)


def unpack(fin, raw=False, verbose=False, strict=False, backtrack=False, try_snappy=True):
    """
    Attempt to parse a sequence of records in a file-like object.

    Returns an iterator, which yields tuples of `UnpackedRecord` and the total number of bytes read so far.

    The flags are the same as those for `read_one_record`.
    """
    record_count = 0
    bad_records = 0
    total_bytes = 0

    while True:
        r = None
        try:
            r, bytes = read_one_record(fin, raw, verbose, strict, try_snappy)
        except Exception as e:
            if strict:
                fin.close()
                raise e
            elif verbose:
                print e

            # if we can backtrack and the message wasn't well formed,
            # backtrack and try to parse the message starting from there
            if backtrack and type(e) in {DecodeError, UnicodeDecodeError}: # these are the exceptions that protobuf will throw
                fin.backtrack()
                continue

        if r is None:
            break

        if verbose and r.error is not None:
            print r.error

        record_count += 1
        total_bytes += bytes

        yield r, total_bytes

    if verbose:
        print "Processed", record_count, "records"

    fin.close()
