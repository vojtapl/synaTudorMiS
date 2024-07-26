from __future__ import annotations

import struct
from hashlib import sha256


class WinTagValContainer:
    def __init__(self, vals: dict = None):
        self.vals = dict(vals) if vals != None else dict()

    def __contains__(self, tag: int):
        return tag in self.vals

    def __getitem__(self, tag: int):
        return self.vals[tag]

    def __setitem__(self, tag: int, data: bytes):
        self.vals[tag] = data

    def __delitem__(self, tag: int):
        del self.vals[tag]

    @staticmethod
    def frombytes(data: bytes) -> WinTagValContainer:
        vals = {}
        while len(data) > 0:
            tag, val_size = struct.unpack("<HI", data[:6])
            assert not tag in vals
            vals[tag] = data[6 : 6 + val_size]

            data = data[6 + val_size :]
        return WinTagValContainer(vals)

    def tobytes(self) -> bytes:
        data = bytes()
        for tag, val in self.vals.items():
            data += struct.pack("<HI", tag, len(val)) + val
        return data

class HashTagValContainer:
    def __init__(self, vals: dict = None, hashes: dict = None):
        self.vals = vals if vals != None else dict()
        self.hashes = hashes if hashes != None else dict()
        if vals is not None and hashes is None:
            self.generate_hashes()

    def __contains__(self, tag: int):
        return tag in self.vals

    def __getitem__(self, tag: int):
        return self.vals[tag]

    def __setitem__(self, tag: int, data: bytes):
        self.vals[tag] = data
        self.hashes[tag] = sha256(data).digest()

    def __delitem__(self, tag: int):
        del self.vals[tag]
        del self.hashes[tag]

    def generate_hashes(self) -> None:
        for tag in self.vals.keys():
            if tag not in self.hashes:
                tag_hash = sha256(self.vals[tag]).digest()
                self.hashes[tag] = tag_hash

    def check_hashes(self) -> bool:
        for tag in self.vals.keys():
            stored_hash = sha256(self.vals[tag]).digest()
            if stored_hash != self.hashes[tag]:
                return False
        return True

    @staticmethod
    def frombytes(data: bytes) -> HashTagValContainer:
        vals = {}
        hashes = {}
        while len(data) > 0:
            tag, val_size = struct.unpack("<HH", data[:4])
            if tag == 0xffff:
                break
            assert not tag in vals
            hashes[tag] = data[4:4+32]
            vals[tag] = data[36:36 + val_size]

            data = data[36 + val_size :]
        return HashTagValContainer(vals, hashes)

    def tobytes(self) -> bytes:
        data = bytes()
        for tag, val in self.vals.items():
            data += struct.pack("<HH", tag, len(val)) + self.hashes[tag] + val
        return data
