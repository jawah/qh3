import sys
import os
import platform
from wheel.bdist_wheel import bdist_wheel

import setuptools

include_dirs = [
    os.path.join("vendor", "ls-qpack"),
    os.path.join("vendor", "ls-qpack", "deps", "xxhash"),
]

if sys.platform == "win32":
    extra_compile_args = []
    libraries = [
        "libcrypto",
        "advapi32",
        "crypt32",
        "gdi32",
        "user32",
        "ws2_32",
    ]
    include_dirs.append(
        os.path.join("vendor", "ls-qpack", "wincompat"),
    )
else:
    extra_compile_args = ["-std=c99"]
    libraries = ["crypto"]


class bdist_wheel_abi3(bdist_wheel):
    def get_tag(self):
        python, abi, plat = super().get_tag()

        if python.startswith("cp"):
            return "cp37", "abi3", plat

        return python, abi, plat


if platform.python_implementation() == "CPython":
    extra_kwarg = {
        "py_limited_api": True,
        "define_macros": [("Py_LIMITED_API", "0x03070000")]
    }
else:
    extra_kwarg = dict()


setuptools.setup(
    ext_modules=[
        setuptools.Extension(
            "qh3._buffer",
            extra_compile_args=extra_compile_args,
            sources=["src/qh3/_buffer.c"],
            **extra_kwarg
        ),
        setuptools.Extension(
            "qh3._vendor.pylsqpack._binding",
            extra_compile_args=extra_compile_args,
            include_dirs=include_dirs,
            sources=[
                "src/qh3/_vendor/pylsqpack/binding.c",
                "vendor/ls-qpack/lsqpack.c",
                "vendor/ls-qpack/deps/xxhash/xxhash.c",
            ],
            **extra_kwarg
        ),
    ],
    cmdclass={"bdist_wheel": bdist_wheel_abi3},
)
