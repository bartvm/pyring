# Ring signatures

Implementation of one-time ring signatures in Python. [Ring signatures](https://en.wikipedia.org/wiki/Ring_signature) allow a user to sign a message as a member of a group, without revealing their identity. One-time ring signatures are a type of ring signature where multiple signatures of the same user can be identified as such. One-time ring signatures were described in the [CryptoNote whitepaper](https://cryptonote.org/whitepaper.pdf) and implemented in, e.g., [Bytecoin](https://github.com/bcndev/bytecoin/blob/07b8bf2a3e327bda902fd00ffbf3bdfcc7f79eb9/src/crypto/crypto.cpp#L235-L270).

## Implementation

This implementation follows the white-paper and Bytecoin implementation. The arithmetic is performed using [Sodium](https://libsodium.gitbook.io/doc/). The code requires version 1.0.18 of Sodium, which has not been released yet. Hence, a bleeding edge version of Sodium is packaged along with the Python code.

## Installation and usage

Clone the repository and use `setup.py` to install the package.

```bash
python setup.py install
```

Alternatively, use `python setup.py build` and `python setup.py develop` to build the library in-place.

A simple command line interface is provided:

```bash
ring-keygen  # Generate a key pair
head -c 100 < /dev/urandom > message  # Generate a random message
ring-sign message ringkey ringkey.pub ringkey2.pub > ring.sig  # Sign the message against two public keys
ring-verify message - < ring.sig  # Verify that the signature is correct
```
