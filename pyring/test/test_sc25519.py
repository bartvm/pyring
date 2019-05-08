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

import pytest

from pyring._sodium import ffi, lib
from pyring.sc25519 import Scalar, L


def test_sc_constructors():
    data = ffi.new("unsigned char[]", lib.crypto_core_ed25519_SCALARBYTES)
    data[0] = 3
    assert Scalar(data) == 3

    assert Scalar(3) == 3

    nonreduced = (L + 3).to_bytes(
        lib.crypto_core_ed25519_NONREDUCEDSCALARBYTES, "little"
    )
    assert Scalar.from_unreduced(nonreduced) == 3

    assert 0 < int(Scalar.random()) < L

    assert Scalar(L + 1) == L + 1
    assert Scalar(L + 1) + 0 == 1

    with pytest.raises(ValueError):
        Scalar(b"0" * (lib.crypto_core_ed25519_SCALARBYTES - 1))

    with pytest.raises(ValueError):
        Scalar.from_unreduced(
            b"0" * (lib.crypto_core_ed25519_NONREDUCEDSCALARBYTES - 1)
        )


def test_sc_repr():
    x = Scalar.random()
    assert eval(repr(x)) == x


def test_sc_arithmetic():
    x = Scalar(L - 2)
    y = Scalar(1)
    z = Scalar(4)

    assert x + y == L - 1
    assert x + x == L - 4
    assert x + 1 == L - 1
    assert x + 3 == y
    assert 1 + x == x + 1

    assert x - y == L - 3
    assert y - x == 3
    assert x - 2 == L - 4
    assert y - 3 == x
    assert 3 - y == -x

    assert -x == 2
    assert -y == L - 1

    assert x * 2 == L - 4
    assert y * x == x
    assert y * 3 == 3
    assert 2 * x == L - 4

    assert (1 / y) * y == 1
    assert (y / 2) * 2 == 1
    assert (y / y) * y == 1

    assert (1 / x) * x == 1
    assert x / 1 == x
    assert x / z * z == x
    assert (z / x) * x == z

    assert x != x + 1
    assert x != object()

    f = 2.3
    with pytest.raises(TypeError):
        x + f
    with pytest.raises(TypeError):
        f + x
    with pytest.raises(TypeError):
        x - f
    with pytest.raises(TypeError):
        f - x
    with pytest.raises(TypeError):
        x / f
    with pytest.raises(TypeError):
        f / x
    with pytest.raises(TypeError):
        f * x
    with pytest.raises(TypeError):
        x * f
