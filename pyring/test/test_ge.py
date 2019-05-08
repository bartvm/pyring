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

import hashlib
import os

import pytest

from pyring._sodium import ffi, lib
from pyring.sc25519 import Scalar, L
from pyring.ge import Point, O, G, hash_to_scalar, Q


def test_point_constructors():
    data = ffi.new("unsigned char[]", lib.crypto_core_ed25519_BYTES)
    data[0] = 3
    p = Point(data)
    assert not p.is_valid()

    digest = hashlib.blake2s(b"data").digest()
    assert len(digest) == lib.crypto_core_ed25519_UNIFORMBYTES
    uniform = ffi.new("unsigned char[]", list(digest))
    p = Point.from_uniform(uniform)
    assert p.is_valid()

    digest = hashlib.blake2b(b"data").digest()
    assert len(digest) == lib.crypto_core_ed25519_HASHBYTES
    uniform = ffi.new("unsigned char[]", list(digest))
    p = Point.from_hash(uniform)
    assert p.is_valid()

    with pytest.raises(ValueError):
        Point(b"0" * (lib.crypto_core_ed25519_BYTES - 1))
    with pytest.raises(ValueError):
        Point.from_hash(b"0" * (lib.crypto_core_ed25519_HASHBYTES - 1))
    with pytest.raises(ValueError):
        Point.from_uniform(b"0" * (lib.crypto_core_ed25519_UNIFORMBYTES - 1))


def test_point_arithmetic():
    p = Point.from_uniform(hashlib.blake2s(b"data").digest())

    assert p + p == 2 * p
    assert 2 * p - p == p
    assert p + O == O + p  # noqa: E741
    assert p + O == p  # noqa: E741

    assert p != 2 * p
    assert p != object()

    fe = Scalar(2)
    f = 2.3
    with pytest.raises(TypeError):
        p + fe
    with pytest.raises(TypeError):
        p - fe
    with pytest.raises(TypeError):
        f * p


def test_generator():
    assert L & 1
    assert 2 * ((L // 2) * G) + G == O
    assert L * G == L * Point(G.data)
    assert G + O == G  # noqa: E741
    assert G + G == 2 * G

    f = 2.3
    with pytest.raises(TypeError):
        f * G


def test_repr():
    p = Point.from_uniform(os.urandom(32))
    assert eval(repr(p)) == p


def test_hash_to_point():
    p = Point.from_uniform(hashlib.blake2s(b"hash input").digest())
    assert p.hash_to_point().is_valid()
    assert p.hash_to_point("blake2s").is_valid()
    assert p.hash_to_point("blake2b").is_valid()

    with pytest.raises(ValueError):
        p.hash_to_point("sha3_224")


def test_hash_to_scalar():
    assert 0 <= hash_to_scalar(b"\ff" * 64) < Q
    assert 0 <= hash_to_scalar(b"\ff" * 64, "blake2s") < Q
    assert 0 <= hash_to_scalar(b"\ff" * 64, "sha3_224") < Q
