# Ring signatures

This is an imlementation of one-time ring signatures in Python. [Ring signatures](https://en.wikipedia.org/wiki/Ring_signature) allow a user to sign a message as a member of a group, without revealing their identity. One-time ring signatures are a type of ring signature where multiple signatures of the same user can be identified as such.

One-time ring signatures are described in a [CryptoNote whitepaper](https://cryptonote.org/whitepaper.pdf) and the accompanying [CrypteNote standard](https://cryptonote.org/cns/cns002.txt) (CC BY-SA 3.0). An implementation [can be found](https://github.com/cryptonotefoundation/cryptonote/blob/8edd998304431c219b432194b7a3847b44b576c3/src/crypto/crypto.cpp#L329-L389) in the reference code of the CryptoNote protocol (MIT/X11).

## Implementation

This implementation follows the white-paper and CryptoNote implementation closely. The arithmetic is performed on the Ed25519 curve using [Sodium](https://libsodium.gitbook.io/doc/advanced/point-arithmetic) (ISC licensed). 

*Note that the code requires version 1.0.18 of Sodium, which has not been released yet. Hence, a bleeding edge version of Sodium is packaged along with the Python code.*

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

## Disclaimer

This is not an officially supported Google product.
