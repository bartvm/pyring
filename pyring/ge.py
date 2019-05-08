# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Elliptic curve arithmetic.

This module contains utitilities to perform elliptic curve arithmetic (adding and
multiplying points on the Ed25519 curve).

Attributes:
    Q: Prime order of the field that the Ed25519 curve is defined over.
    O: The identity element of the Ed25519 curve.
    G: The generator (base point) of the Ed25519 curve.

"""
from __future__ import annotations

import hashlib
from typing import Any, cast

from .utils import as_array, ByteLike
from .sc25519 import ScalarLike, Scalar
from ._sodium import lib

# Calculate the base point (generator) so that it can be used in additions/subtractions
# We need to find 4 / 5 on the prime field defined by prime q = 2^255 - 19
Q = 2 ** 255 - 19
# NB: Fermat's little theorem
_GENERATOR_DATA = (4 * pow(5, Q - 2, Q)).to_bytes(
    lib.crypto_core_ed25519_BYTES, "little"
)
_IDENTITY_DATA = (1).to_bytes(lib.crypto_core_ed25519_BYTES, "little")


class Point:
    """A point on the Ed25519 curve.

    A point on a twisted Edwards curve over the prime field with order 2^255 - 19. The
    base point of the curve is (x, 4/5) with x "positive" (meaning its first bit is not
    set). The order of this curve is L = 2^252 + 2774...

    Attributes:
        data: The point stored as its y coordinate using a 32-byte integer in little-
            endian format. The last bit is used to store the parity of x.
    """

    __slots__ = ["data"]

    def __init__(self, data: ByteLike = _IDENTITY_DATA) -> None:
        if len(data) != lib.crypto_core_ed25519_BYTES:
            raise ValueError(f"data must be {lib.crypto_core_ed25519_BYTES} bytes")
        self.data = as_array(data)

    def __repr__(self) -> str:
        return f"Point({self.as_bytes()})"

    def __hash__(self) -> int:
        return hash(repr(self))

    def as_bytes(self) -> bytes:
        return bytes(self.data)

    @classmethod
    def from_uniform(cls, n: ByteLike) -> Point:
        """Map a set of 32-bytes to a point on the curve."""
        out = cls()
        if len(n) != lib.crypto_core_ed25519_UNIFORMBYTES:
            raise ValueError(
                f"uniform data must be {lib.crypto_core_ed25519_UNIFORMBYTES} bytes"
            )
        lib.crypto_core_ed25519_from_uniform(out.data, as_array(n))
        return out

    @classmethod
    def from_hash(cls, n: ByteLike) -> Point:
        out = cls()
        if len(n) != lib.crypto_core_ed25519_HASHBYTES:
            raise ValueError(f"hash must be {lib.crypto_core_ed25519_HASHBYTES} bytes")
        lib.crypto_core_ed25519_from_hash(out.data, as_array(n))
        return out

    def is_valid(self) -> bool:
        return cast(bool, lib.crypto_core_ed25519_is_valid_point(self.data) == 1)

    def __add__(self, other: Point) -> Point:
        """Add two points."""
        if not isinstance(other, Point):
            return NotImplemented
        out = Point()
        lib.crypto_core_ed25519_add(out.data, self.data, other.data)
        return out

    def __sub__(self, other: Point) -> Point:
        """Subtract two points."""
        if not isinstance(other, Point):
            return NotImplemented
        out = Point()
        lib.crypto_core_ed25519_sub(out.data, self.data, other.data)
        return out

    def __rmul__(self, other: ScalarLike) -> Point:
        """Left-multiply the point by a scalar."""
        if isinstance(other, int):
            other = Scalar(other)
        elif not isinstance(other, Scalar):
            return NotImplemented
        out = Point()
        lib.crypto_scalarmult_ed25519_noclamp(out.data, other.data, self.data)
        return out

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, Point):
            return bytes(self.data) == bytes(other.data)
        else:
            return False

    def hash_to_point(self, hash_name: str = "sha3_512") -> Point:
        digest = hashlib.new(hash_name, bytes(self.data)).digest()
        if len(digest) == lib.crypto_core_ed25519_HASHBYTES:
            return Point.from_hash(digest)
        elif len(digest) == lib.crypto_core_ed25519_UNIFORMBYTES:
            return Point.from_uniform(digest)
        else:
            raise ValueError(f"hash function returned {len(digest)} bytes")


class Generator(Point):
    """The generator (base point) of the Ed25519 curve.

    Multiplication with the base point is special cased.
    """

    def __init__(self) -> None:
        super().__init__(_GENERATOR_DATA)

    def __rmul__(self, other: ScalarLike) -> Point:
        if isinstance(other, int):
            other = Scalar(other)
        elif not isinstance(other, Scalar):
            return NotImplemented
        out = Point()
        lib.crypto_scalarmult_ed25519_base_noclamp(out.data, other.data)
        return out


O = Point()  # noqa: 741
G = Generator()


def hash_to_scalar(data: ByteLike, hash_name: str = "sha3_512") -> int:
    """Hash data to an integer mod Q.

    Args:
        data: An object convertible to bytes that will be hashed.
        hash: The hashing algorithm to use.

    Returns:
        An integer in the range [0, ..., Q - 1] where Q = 2^255 - 19.

    """
    digest = hashlib.new(hash_name, bytes(data)).digest()
    return int.from_bytes(digest, "little") % Q
