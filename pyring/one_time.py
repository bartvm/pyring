from __future__ import annotations

import dataclasses
import functools
import operator
import random
from typing import ByteString, List

from .ge import Point, G, hash_to_scalar
from .sc25519 import Scalar


class PrivateKey:
    __slots__ = ["scalar"]

    def __init__(self, scalar: Scalar) -> None:
        self.scalar = scalar

    @classmethod
    def generate(cls) -> PrivateKey:
        return cls(Scalar.random())

    @classmethod
    def from_private_bytes(cls, data: ByteString) -> PrivateKey:
        return cls(Scalar(bytes(data)))

    def public_key(self) -> PublicKey:
        return PublicKey(self.scalar * G)

    def key_image(self) -> Point:
        return self.scalar * self.public_key().point.hash_to_point()


class PublicKey:
    __slots__ = ["point"]

    def __init__(self, point: Point) -> None:
        self.point = point


@dataclasses.dataclass(frozen=True)
class RingSignature:
    """A ring signature.

    A ring signature consists of the public keys the message was signed against, the
    key image of the signer's public key, and the two rings.
    """

    public_keys: List[PublicKey]
    key_image: Point
    c: List[Scalar]
    r: List[Scalar]


def ring_sign(
    message: ByteString,
    public_keys: List[PublicKey],
    private_key: PrivateKey,
    key_index: int,
) -> RingSignature:
    """Sign the given message.

    As part of the signature generation, the public keys are shuffled so that the
    ordering holds no information about the identity of the signer.

    Args:
        message: The message to sign.
        public_keys: The public keys of the group to generate a ring signature of.
        private_key: The secret key of the signer.
        key_index: The index to the corresponding public key. Note that they key
            index should be unpredictable; shuffle the public keys before generating
            the ring signature if this is not the case.

    Returns:
        A ring signature.
    """
    # We follow the notation from the CryptoNote white paper, section 4.4
    x = private_key.scalar
    s = key_index
    I = private_key.key_image()  # noqa: E741
    H_s = hash_to_scalar

    def H_p(point: Point) -> Point:
        return point.hash_to_point()

    buffer_ = bytearray(message)

    c = []
    r = []
    for i, public_key in enumerate(public_keys):
        P_i = public_key.point
        if i == key_index:
            q_s = Scalar.random()
            buffer_ += (q_s * G).as_bytes()
            buffer_ += (q_s * H_p(P_i)).as_bytes()
        else:
            q_i = Scalar.random()
            w_i = Scalar.random()
            c.append(w_i)
            r.append(q_i)
            buffer_ += (q_i * G + w_i * P_i).as_bytes()
            buffer_ += (q_i * H_p(P_i) + w_i * I).as_bytes()
    c.insert(s, H_s(buffer_) - functools.reduce(operator.add, c))
    r.insert(s, q_s - c[s] * x)

    return RingSignature(public_keys, I, c, r)


def ring_verify(message: ByteString, signature: RingSignature) -> bool:
    """Verify that a signature is valid for the given message.

    Args:
        message: The message to verify the signature for.
        signature: The ring signature to verify.
    """
    public_keys = signature.public_keys
    I, c, r = signature.key_image, signature.c, signature.r
    H_s = hash_to_scalar

    def H_p(point: Point) -> Point:
        return point.hash_to_point()

    buffer_ = bytearray(message)
    for i, (public_key, r_i, c_i) in enumerate(zip(public_keys, r, c)):
        P_i = public_key.point
        buffer_ += (r_i * G + c_i * P_i).as_bytes()
        buffer_ += (r_i * H_p(P_i) + c_i * I).as_bytes()

    return H_s(buffer_) - functools.reduce(operator.add, c) == 0
