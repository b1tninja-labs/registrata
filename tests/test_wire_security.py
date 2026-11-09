import pytest

from registrata.client import RwhoisClient
from registrata.errors import RwhoisError, RwhoisProtocolError
from registrata.wire import LineReader


class FakeSocket:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.pos = 0

    def recv(self, size):
        if self.pos >= len(self.chunks):
            return b""
        chunk = self.chunks[self.pos]
        if len(chunk) <= size:
            self.pos += 1
            return chunk
        self.chunks[self.pos] = chunk[size:]
        return chunk[:size]


class FakeReader:
    def __init__(self, lines):
        self.lines = list(lines)

    def readline(self):
        if not self.lines:
            raise ConnectionError("closed")
        return self.lines.pop(0)


def test_line_reader_reads_normal_crlf_line():
    reader = LineReader(FakeSocket([b"hello\r\n"]))
    assert reader.readline() == "hello"


def test_line_reader_rejects_oversized_line():
    reader = LineReader(FakeSocket([b"x" * 100]), max_line_bytes=10)
    with pytest.raises(RwhoisProtocolError):
        reader.readline()


def test_client_response_line_limit():
    client = RwhoisClient("example.invalid", 0, max_response_lines=2)
    client._reader = FakeReader(["a", "b", "c", "%ok"])
    with pytest.raises(RwhoisError):
        client._read_until_end()
