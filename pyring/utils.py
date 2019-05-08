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
