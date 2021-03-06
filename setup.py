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

import distutils
import glob
import os
import pathlib
from typing import List

import setuptools
from setuptools.command.build_ext import build_ext as _build_ext
from setuptools.command.build_clib import build_clib as _build_clib


class Distribution(setuptools.Distribution):
    def has_c_libraries(self) -> bool:
        return True


class build_ext(_build_ext):
    def run(self) -> None:
        # Ensure that the bindings can build against packaged libsodium
        build_clib = self.get_finalized_command("build_clib")
        self.include_dirs.append(os.path.join(build_clib.build_clib, "include"))
        self.library_dirs.insert(0, os.path.join(build_clib.build_clib, "lib"))

        # Anaconda has older libsodium headers and libraries that we need to
        # avoid linking against, but include and library directories we pass
        # will always be added after the ones in CFLAGS and LDSHARED. So, if
        # the user doesn't pass these explicitly, we will temporarily remove them.
        cvs = distutils.sysconfig._config_vars
        assert cvs
        prev = cvs.copy()
        if "LDSHARED" not in os.environ:
            cvs["LDSHARED"] = " ".join(
                flag for flag in cvs["LDSHARED"].split(" ") if not flag.startswith("-L")
            )
        if "CFLAGS" not in os.environ:
            cvs["CFLAGS"] = " ".join(
                flag for flag in cvs["CFLAGS"].split(" ") if not flag.startswith("-I")
            )

        # Build the bindings
        super().run()

        # Restore the compiler settings
        distutils.sysconfig._config_vars = prev


class build_clib(_build_clib):
    def get_source_files(self) -> List[str]:
        return []

    def get_library_names(self) -> List[str]:
        return ["sodium"]

    def run(self) -> None:
        build_temp = pathlib.Path(self.build_temp).resolve()
        build_temp.mkdir(parents=True, exist_ok=True)

        # We package a stable version of libsodium with the library
        src_dir = pathlib.Path("libsodium").resolve()
        root_dir = os.getcwd()

        # Now build libsodium statically (to avoid linker issues)
        os.chdir(build_temp)
        self.spawn([f"{src_dir}/configure", f"--prefix={build_temp}",
                    "--disable-shared", "--with-pic"])
        self.spawn(["make"])
        self.spawn(["make", "install"])

        os.chdir(root_dir)


with open("README.md", "r") as fh:
    long_description = fh.read()


setuptools.setup(
    name="pyring",
    version="0.0.2",
    author="Bart van Merriënboer",
    author_email="bart.vanmerrienboer@gmail.com",
    description="Ring signatures",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/bartvm/pyring",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "License :: OSI Approved :: ISC License (ISCL)",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography",
    ],
    cmdclass={"build_ext": build_ext, "build_clib": build_clib},
    distclass=Distribution,
    cffi_modules=["bindings/build.py:ffi"],
    ext_package="pyring",
    setup_requires=["cffi"],
    zip_safe=False,
    install_requires=["cryptography", "cffi"],
    scripts=glob.glob("bin/*"),
)
