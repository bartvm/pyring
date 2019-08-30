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

from typing import Any, Union

from .utils import as_array, ByteLike
from ._sodium import lib

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
        data: The FFI array storing the scalar. Numbers are stored as 32-byte
            unsigned integers in little-endian format.
    """

    __slots__ = ["data"]

    def __init__(self, n: Union[ByteLike, int] = 0) -> None:
        """Construct a scalar.

        Args:
            n: The 32-byte array or ffi array to initialize this scalar with. If an
                integer is passed it will be converted to bytes (without applying the
                modulo operator).
        """
        if isinstance(n, int):
            n = n.to_bytes(lib.crypto_core_ed25519_SCALARBYTES, "little")
        if len(n) != lib.crypto_core_ed25519_SCALARBYTES:
            raise ValueError(
                f"scalar must be {lib.crypto_core_ed25519_SCALARBYTES} bytes"
            )
        self.data = as_array(n)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({int(self)})"

    @classmethod
    def from_unreduced(cls, n: ByteLike) -> Scalar:
        """Reduces a 64-byte scalar to a 32-byte scalar by applying mod L.

        Returns:
            A scalar in the range [0, ..., L - 1].
        """
        if len(n) != lib.crypto_core_ed25519_NONREDUCEDSCALARBYTES:
            raise ValueError(
                "unreduced scalar must be "
                f"{lib.crypto_core_ed25519_NONREDUCEDSCALARBYTES} bytes"
            )
        out = cls()
        lib.crypto_core_ed25519_scalar_reduce(out.data, as_array(n))
        return out

    @classmethod
    def random(cls) -> Scalar:
        """Construct a random scalar.

        Returns:
            A scalar in the range [1, ..., L - 1].
        """
        out = cls()
        lib.crypto_core_ed25519_scalar_random(out.data)
        return out

    def __int__(self) -> int:
        return int.from_bytes(bytes(self.data), "little")

    def __add__(self, other: ScalarLike) -> Scalar:
        if isinstance(other, int):
            other = Scalar(other)
        elif not isinstance(other, Scalar):
            return NotImplemented
        out = Scalar()
        lib.crypto_core_ed25519_scalar_add(out.data, self.data, other.data)
        return out

    def __radd__(self, other: ScalarLike) -> Scalar:
        return self + other

    def __sub__(self, other: ScalarLike) -> Scalar:
        if isinstance(other, int):
            other = Scalar(other)
        elif not isinstance(other, Scalar):
            return NotImplemented
        out = Scalar()
        lib.crypto_core_ed25519_scalar_sub(out.data, self.data, other.data)
        return out

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
        out = Scalar()
        lib.crypto_core_ed25519_scalar_mul(out.data, self.data, other.data)
        return out

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
        inverted = Scalar()
        lib.crypto_core_ed25519_scalar_invert(inverted.data, other.data)
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
        out = Scalar()
        lib.crypto_core_ed25519_scalar_negate(out.data, self.data)
        return out

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, int):
            return int(self) == other
        elif isinstance(other, Scalar):
            return bytes(self.data) == bytes(other.data)
        else:
            return False


ScalarLike = Union[Scalar, int]
