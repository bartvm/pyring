import collections
from typing import Union

from ._sodium import ffi


ByteLike = Union[ffi.CData, collections.abc.ByteString]


def as_array(data: ByteLike) -> ffi.CData:
    """Convert a bytes-like object into an FFI-array.

    Args:
        data: An object that can convert to a list of integers.
            If an FFI array is passed, it will be returned as is.

    Returns:
        An FFI `CData` array with the given value.

    """
    if isinstance(data, ffi.CData):
        return data
    array = ffi.new("unsigned char[]", list(data))
    return array
