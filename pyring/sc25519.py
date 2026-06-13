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

This module contains utitilities to perform as modular arithmetic on the prime
field defined by the order of the Ed25519 curve (NB: not the order of the
field that the curve is defined over).

Attributes:
    L: The order of the Ed25519 curve.
"""
from __future__ import annotations

import os
from collections.abc import Buffer
from typing import Any

import nacl.bindings as sodium

L = 2 ** 252 + 27742317777372353535851937790883648493


class Scalar:
    """A scalar in a finite field.

    Arithmetic between scalars is performed modulo L, where L = 2^252 + 2774... is the
    prime order of the cyclic subgroup of curves Ed25519 and Curve25519. NB: This is not
    the prime field that the curve is defined over, which has order 2^255 - 19!
    Arithmetic is performed using libsodium.

    Note that a scalar is not guaranteed to be less than L if it was not a result of
    an arithmetic operation.

    Attributes:
        data: The scalar stored as a 32-byte unsigned integer in little-endian
            format.
    """

    __slots__ = ["data"]

    def __init__(self, n: Buffer | int = 0) -> None:
        """Construct a scalar.

        Args:
            n: The 32-byte array to initialize this scalar with. If an integer is
                passed it will be converted to bytes (without applying the modulo
                operator).
        """
        if isinstance(n, int):
            n = n.to_bytes(sodium.crypto_core_ed25519_SCALARBYTES, "little")
        if len(n) != sodium.crypto_core_ed25519_SCALARBYTES:
            raise ValueError(
                f"scalar must be {sodium.crypto_core_ed25519_SCALARBYTES} bytes"
            )
        self.data = bytes(n)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({int(self)})"

    @classmethod
    def from_unreduced(cls, n: Buffer) -> Scalar:
        """Reduces a 64-byte scalar to a 32-byte scalar by applying mod L.

        Returns:
            A scalar in the range [0, ..., L - 1].
        """
        if len(n) != sodium.crypto_core_ed25519_NONREDUCEDSCALARBYTES:
            raise ValueError(
                "unreduced scalar must be "
                f"{sodium.crypto_core_ed25519_NONREDUCEDSCALARBYTES} bytes"
            )
        return cls(sodium.crypto_core_ed25519_scalar_reduce(bytes(n)))

    @classmethod
    def random(cls) -> Scalar:
        """Construct a random scalar.

        Returns:
            A scalar in the range [1, ..., L - 1].
        """
        return cls.from_unreduced(
            os.urandom(sodium.crypto_core_ed25519_NONREDUCEDSCALARBYTES)
        )

    def __int__(self) -> int:
        return int.from_bytes(self.data, "little")

    def __add__(self, other: ScalarLike) -> Scalar:
        if isinstance(other, int):
            other = Scalar(other)
        elif not isinstance(other, Scalar):
            return NotImplemented
        return Scalar(sodium.crypto_core_ed25519_scalar_add(self.data, other.data))

    def __radd__(self, other: ScalarLike) -> Scalar:
        return self + other

    def __sub__(self, other: ScalarLike) -> Scalar:
        if isinstance(other, int):
            other = Scalar(other)
        elif not isinstance(other, Scalar):
            return NotImplemented
        return Scalar(sodium.crypto_core_ed25519_scalar_sub(self.data, other.data))

    def __rsub__(self, other: ScalarLike) -> Scalar:
        if isinstance(other, int):
            other = Scalar(other)
        elif not isinstance(other, Scalar):
            return NotImplemented
        return other - self

    def __mul__(self, other: ScalarLike) -> Scalar:
        """Multiply two scalars modulus L."""
        if isinstance(other, int):
            other = Scalar(other)
        elif not isinstance(other, Scalar):
            return NotImplemented
        return Scalar(sodium.crypto_core_ed25519_scalar_mul(self.data, other.data))

    def __rmul__(self, other: ScalarLike) -> Scalar:
        return self * other

    def __truediv__(self, other: ScalarLike) -> Scalar:
        """Divide two scalars.

        Division is implemented as inversion followed by multiplication.
        """
        if isinstance(other, int):
            other = Scalar(other)
        elif not isinstance(other, Scalar):
            return NotImplemented
        inverted = Scalar(sodium.crypto_core_ed25519_scalar_invert(other.data))
        if self == 1:
            return inverted
        return self * inverted

    def __rtruediv__(self, other: ScalarLike) -> Scalar:
        if isinstance(other, int):
            other = Scalar(other)
        elif not isinstance(other, Scalar):
            return NotImplemented
        return other / self

    def __neg__(self) -> Scalar:
        return Scalar(sodium.crypto_core_ed25519_scalar_negate(self.data))

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, int):
            return int(self) == other
        elif isinstance(other, Scalar):
            return self.data == other.data
        else:
            return False


ScalarLike = Scalar | int
