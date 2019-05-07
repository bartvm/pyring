import glob
import os

from cffi import FFI

HEADERS = glob.glob(os.path.join(os.path.abspath(os.path.dirname(__file__)), "*.h"))


ffi = FFI()
for header in HEADERS:
    with open(header, "r") as hfile:
        ffi.cdef(hfile.read())
source = """
#include <sodium.h>
"""
ffi.set_source("_sodium", source, libraries=["sodium"])
