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
    include_dirs.append(
        os.path.join("vendor", "ls-qpack", "wincompat"),
    )
else:
    extra_compile_args = ["-std=c99"]


class bdist_wheel_abi3(bdist_wheel):
    def get_tag(self):
        python, abi, plat = super().get_tag()

        if python.startswith("cp"):
            return "cp37", "abi3", plat

        return python, abi, plat


extra_kwarg = {}

if platform.python_implementation() == "CPython":
    extra_kwarg.update(
        {
            "py_limited_api": True,
            "define_macros": [("Py_LIMITED_API", "0x03070000")],
        }
    )


setuptools.setup(
    ext_modules=[
        setuptools.Extension(
            "qh3._vendor.pylsqpack._binding",
            extra_compile_args=extra_compile_args,
            include_dirs=include_dirs,
            sources=[
                "src/qh3/_vendor/pylsqpack/binding.c",
                "vendor/ls-qpack/lsqpack.c",
                "vendor/ls-qpack/deps/xxhash/xxhash.c",
            ],
            **extra_kwarg,
        ),
    ],
    cmdclass={"bdist_wheel": bdist_wheel_abi3},
)
