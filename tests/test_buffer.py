from __future__ import annotations

import pytest

from qh3.buffer import Buffer, BufferReadError, BufferWriteError, size_uint_var


class TestBuffer:
    def test_data_slice(self):
        buf = Buffer(data=b"\x08\x07\x06\x05\x04\x03\x02\x01")
        assert buf.data_slice(0, 8) == b"\x08\x07\x06\x05\x04\x03\x02\x01"
        assert buf.data_slice(1, 3) == b"\x07\x06"

        with pytest.raises(OverflowError):
            buf.data_slice(-1, 3)
        with pytest.raises(BufferReadError):
            buf.data_slice(0, 9)
        with pytest.raises(BufferReadError):
            buf.data_slice(1, 0)

    def test_pull_bytes(self):
        buf = Buffer(data=b"\x08\x07\x06\x05\x04\x03\x02\x01")
        assert buf.pull_bytes(3) == b"\x08\x07\x06"

    def test_internal_fixed_size(self):
        buf = Buffer(8)

        buf.push_bytes(b"foobar")  # push 6 bytes, 2 left free bytes
        assert buf.data == b"foobar"
        buf.seek(8)  # setting cursor to the end of buf capacity
        assert buf.data == b"foobar\x00\x00"# the two NULL bytes should be there

    def test_internal_push_zero_bytes(self):
        buf = Buffer(6)

        buf.push_bytes(b"foobar")  # push 6 bytes, 0 left free bytes
        assert buf.data == b"foobar"
        assert buf.push_bytes(b"") is None # this should not trigger any exception
        with pytest.raises(BufferWriteError):
            buf.push_bytes(b"x")  # this should!

    def test_pull_bytes_negative(self):
        buf = Buffer(data=b"\x08\x07\x06\x05\x04\x03\x02\x01")
        with pytest.raises(OverflowError):
            buf.pull_bytes(-1)

    def test_pull_bytes_truncated(self):
        buf = Buffer(capacity=0)
        with pytest.raises(BufferReadError):
            buf.pull_bytes(2)
        assert buf.tell() == 0

    def test_pull_bytes_zero(self):
        buf = Buffer(data=b"\x08\x07\x06\x05\x04\x03\x02\x01")
        assert buf.pull_bytes(0) == b""

    def test_pull_uint8(self):
        buf = Buffer(data=b"\x08\x07\x06\x05\x04\x03\x02\x01")
        assert buf.pull_uint8() == 0x08
        assert buf.tell() == 1

    def test_pull_uint8_truncated(self):
        buf = Buffer(capacity=0)
        with pytest.raises(BufferReadError):
            buf.pull_uint8()
        assert buf.tell() == 0

    def test_pull_uint16(self):
        buf = Buffer(data=b"\x08\x07\x06\x05\x04\x03\x02\x01")
        assert buf.pull_uint16() == 0x0807
        assert buf.tell() == 2

    def test_pull_uint16_truncated(self):
        buf = Buffer(capacity=1)
        with pytest.raises(BufferReadError):
            buf.pull_uint16()
        assert buf.tell() == 0

    def test_pull_uint32(self):
        buf = Buffer(data=b"\x08\x07\x06\x05\x04\x03\x02\x01")
        assert buf.pull_uint32() == 0x08070605
        assert buf.tell() == 4

    def test_pull_uint32_truncated(self):
        buf = Buffer(capacity=3)
        with pytest.raises(BufferReadError):
            buf.pull_uint32()
        assert buf.tell() == 0

    def test_pull_uint64(self):
        buf = Buffer(data=b"\x08\x07\x06\x05\x04\x03\x02\x01")
        assert buf.pull_uint64() == 0x0807060504030201
        assert buf.tell() == 8

    def test_pull_uint64_truncated(self):
        buf = Buffer(capacity=7)
        with pytest.raises(BufferReadError):
            buf.pull_uint64()
        assert buf.tell() == 0

    def test_push_bytes(self):
        buf = Buffer(capacity=3)
        buf.push_bytes(b"\x08\x07\x06")
        assert buf.data == b"\x08\x07\x06"
        assert buf.tell() == 3

    def test_push_bytes_truncated(self):
        buf = Buffer(capacity=3)
        with pytest.raises(BufferWriteError):
            buf.push_bytes(b"\x08\x07\x06\x05")
        assert buf.tell() == 0

    def test_push_bytes_zero(self):
        buf = Buffer(capacity=3)
        buf.push_bytes(b"")
        assert buf.data == b""
        assert buf.tell() == 0

    def test_push_uint8(self):
        buf = Buffer(capacity=1)
        buf.push_uint8(0x08)
        assert buf.data == b"\x08"
        assert buf.tell() == 1

    def test_push_uint16(self):
        buf = Buffer(capacity=2)
        buf.push_uint16(0x0807)
        assert buf.data == b"\x08\x07"
        assert buf.tell() == 2

    def test_push_uint32(self):
        buf = Buffer(capacity=4)
        buf.push_uint32(0x08070605)
        assert buf.data == b"\x08\x07\x06\x05"
        assert buf.tell() == 4

    def test_push_uint64(self):
        buf = Buffer(capacity=8)
        buf.push_uint64(0x0807060504030201)
        assert buf.data == b"\x08\x07\x06\x05\x04\x03\x02\x01"
        assert buf.tell() == 8

    def test_seek(self):
        buf = Buffer(data=b"01234567")
        assert not buf.eof()
        assert buf.tell() == 0

        buf.seek(4)
        assert not buf.eof()
        assert buf.tell() == 4

        buf.seek(8)
        assert buf.eof()
        assert buf.tell() == 8

        with pytest.raises(OverflowError):
            buf.seek(-1)
        assert buf.tell() == 8
        with pytest.raises(BufferReadError):
            buf.seek(9)
        assert buf.tell() == 8


class TestUintVar:
    def roundtrip(self, data, value):
        buf = Buffer(data=data)
        assert buf.pull_uint_var() == value
        assert buf.tell() == len(data)

        buf = Buffer(capacity=8)
        buf.push_uint_var(value)
        assert buf.data == data

    def test_uint_var(self):
        # 1 byte
        self.roundtrip(b"\x00", 0)
        self.roundtrip(b"\x01", 1)
        self.roundtrip(b"\x25", 37)
        self.roundtrip(b"\x3f", 63)

        # 2 bytes
        self.roundtrip(b"\x7b\xbd", 15293)
        self.roundtrip(b"\x7f\xff", 16383)

        # 4 bytes
        self.roundtrip(b"\x9d\x7f\x3e\x7d", 494878333)
        self.roundtrip(b"\xbf\xff\xff\xff", 1073741823)

        # 8 bytes
        self.roundtrip(b"\xc2\x19\x7c\x5e\xff\x14\xe8\x8c", 151288809941952652)
        self.roundtrip(b"\xff\xff\xff\xff\xff\xff\xff\xff", 4611686018427387903)

    def test_pull_uint_var_truncated(self):
        buf = Buffer(capacity=0)
        with pytest.raises(BufferReadError):
            buf.pull_uint_var()

        buf = Buffer(data=b"\xff")
        with pytest.raises(BufferReadError):
            buf.pull_uint_var()

    def test_push_uint_var_too_big(self):
        buf = Buffer(capacity=8)
        with pytest.raises(ValueError) as cm:
            buf.push_uint_var(4611686018427387904)
        assert str(cm.value) == "Integer is too big for a variable-length integer"

    def test_size_uint_var(self):
        assert size_uint_var(63) == 1
        assert size_uint_var(16383) == 2
        assert size_uint_var(1073741823) == 4
        assert size_uint_var(4611686018427387903) == 8

        with pytest.raises(ValueError) as cm:
            size_uint_var(4611686018427387904)
        assert str(cm.value) == "Integer is too big for a variable-length integer"
