import distutils
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
            cvs["LDSHARED"] = " ".join(flag for flag in cvs["LDSHARED"].split(" ")
                                       if not flag.startswith("-L"))
        if "CFLAGS" not in os.environ:
            cvs["CFLAGS"] = " ".join(flag for flag in cvs["CFLAGS"].split(" ")
                                     if not flag.startswith("-I"))

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

        src_dir = pathlib.Path("libsodium").resolve()

        # We build and install in the temporary directory
        root = os.getcwd()
        # We use the master branch because we need features from the
        # unreleased 1.0.18 version, but the master branch requires
        # us to run autotools.
        os.chdir(src_dir)
        self.spawn(["./autogen.sh"])
        os.chdir(build_temp)
        self.spawn([f"{src_dir}/configure", f"--prefix={build_temp}",
                    # Link statically to avoid loading issues
                    "--disable-shared", "--with-pic"])
        self.spawn(["make"])
        self.spawn(["make", "install"])
        os.chdir(root)


with open("README.md", "r") as fh:
    long_description = fh.read()


setuptools.setup(
    name="pyring",
    version="0.0.1",
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
)
