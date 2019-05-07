from . import _sodium

if _sodium.lib.sodium_init() < 0:
    raise RuntimeError("cannot initialize libsodium")  # pragma: no cover
