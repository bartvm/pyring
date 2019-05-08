import dataclasses
import os
import random

from pyring.one_time import PrivateKey, ring_sign, ring_verify
from pyring.sc25519 import Scalar


def test_keys():
    private_key = PrivateKey.generate()
    public_key = private_key.public_key()
    assert public_key.point.is_valid()

    private_key = PrivateKey.from_private_bytes(bytes(Scalar.random().data))


def test_one_time():
    num_keys = 100
    signer_index = 0
    # Let each user sign
    public_keys = []
    # Generate keys
    for key_index in range(num_keys):
        private_key = PrivateKey.generate()
        public_key = private_key.public_key()
        public_keys.append(public_key.point)
        if key_index == signer_index:
            signer_key = private_key

    message = os.urandom(random.randint(1, 500))
    signature = ring_sign(message, public_keys, signer_key.scalar, signer_index)

    # Check the signature works
    assert len(signature.c) == num_keys
    assert len(signature.r) == num_keys
    assert len(signature.public_keys) == num_keys

    assert ring_verify(message, signature)

    # Check it does not work for other messages and such
    assert not ring_verify(message + b"0", signature)
    wrong_public_keys = dataclasses.replace(signature, public_keys=public_keys[::-1])
    assert not ring_verify(message, wrong_public_keys)
    wrong_image = dataclasses.replace(signature, key_image=2 * signature.key_image)
    assert not ring_verify(message, wrong_image)
    signature.c[0] += 1
    assert not ring_verify(message, signature)
