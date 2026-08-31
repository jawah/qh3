from __future__ import annotations

import os
import sys
from pathlib import Path

import nox


def tests_impl(
    session: nox.Session,
    tracemalloc_enable: bool = False,
) -> None:
    # Install deps and the package itself.
    session.install("-U", "pip", "maturin", silent=False)
    session.install("-r", "dev-requirements.txt", silent=False)

    session.run("maturin", "develop", "--release")

    if session.python != "pypy":
        python_executable = session.run(
            "python",
            "-c",
            "import sys; print(sys.executable)",
            silent=True,
        ).strip()
        rust_env = {"PYO3_PYTHON": python_executable}
        if sys.platform != "win32":
            library_path_variable = (
                "DYLD_LIBRARY_PATH" if sys.platform == "darwin" else "LD_LIBRARY_PATH"
            )
            python_library_path = session.run(
                "python",
                "-c",
                "import sysconfig; print(sysconfig.get_config_var('LIBDIR') or '')",
                silent=True,
            ).strip()
            inherited_library_path = os.environ.get(library_path_variable)
            rust_env[library_path_variable] = os.pathsep.join(
                path for path in (python_library_path, inherited_library_path) if path
            )
        session.run(
            "cargo",
            "test",
            "--no-default-features",
            env=rust_env,
            external=True,
        )

    # Show the pip version.
    session.run("pip", "--version")
    # Print the Python version and bytesize.
    session.run("python", "--version")
    session.run("python", "-c", "import struct; print(struct.calcsize('P') * 8)")

    session.run(
        "python",
        "-m",
        *(
            (
                "coverage",
                "run",
                "--parallel-mode",
                "-m",
            )
            if tracemalloc_enable is False
            else ()
        ),
        "pytest",
        "-v",
        "-ra",
        f"--color={'yes' if 'GITHUB_ACTIONS' in os.environ else 'auto'}",
        "--tb=native",
        "--durations=10",
        "--strict-config",
        "--strict-markers",
        *(session.posargs or ("tests/",)),
        env={
            "PYTHONWARNINGS": "always::DeprecationWarning",
            "COVERAGE_CORE": "sysmon",
            "PYTHONTRACEMALLOC": "25" if tracemalloc_enable else "",
        },
    )


@nox.session(
    python=["3.7", "3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "pypy"]
)
def test(session: nox.Session) -> None:
    tests_impl(session)


@nox.session(python=["3.7", "3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14"])
def tracemalloc(session: nox.Session) -> None:
    tests_impl(session, tracemalloc_enable=True)


def git_clone(session: nox.Session, git_url: str) -> None:
    """We either clone the target repository or if already exist
    simply reset the state and pull.
    """
    expected_directory = git_url.split("/")[-1]

    if expected_directory.endswith(".git"):
        expected_directory = expected_directory[:-4]

    if not os.path.isdir(expected_directory):
        session.run("git", "clone", "--depth", "1", git_url, external=True)
    else:
        session.run(
            "git", "-C", expected_directory, "reset", "--hard", "HEAD", external=True
        )
        session.run("git", "-C", expected_directory, "pull", external=True)


@nox.session()
def downstream_niquests(session: nox.Session) -> None:
    root = os.getcwd()
    tmp_dir = session.create_tmp()

    session.cd(tmp_dir)
    git_clone(session, "https://github.com/jawah/niquests")
    git_clone(session, "https://github.com/jawah/urllib3.future")

    urllib3_root = Path(root) / tmp_dir / "urllib3.future"
    urllib3_pyproject = urllib3_root / "pyproject.toml"
    urllib3_metadata = urllib3_pyproject.read_text(encoding="utf-8")
    # Remove this metadata-only bypass once urllib3-future allows qh3 2.x.
    qh3_requirement = "qh3>=1.5.4,<2.0.0"
    if qh3_requirement in urllib3_metadata:
        urllib3_metadata = urllib3_metadata.replace(
            qh3_requirement, "qh3>=1.5.4,<3.0.0"
        )
        urllib3_pyproject.write_text(urllib3_metadata, encoding="utf-8")
    else:
        assert "qh3>=1.5.4,<3.0.0" in urllib3_metadata
    remote_address = """remote_address=(
                        self.__custom_tls_settings.assert_hostname
                        if self.__custom_tls_settings.assert_hostname
                        else server,
                        int(port),
                    ),"""
    for relative_path in (
        "src/urllib3/backend/hface.py",
        "src/urllib3/backend/_async/hface.py",
    ):
        backend = urllib3_root / relative_path
        source = backend.read_text(encoding="utf-8")
        if remote_address in source:
            backend.write_text(
                source.replace(
                    remote_address, "remote_address=self.sock.getpeername(),"
                ),
                encoding="utf-8",
            )
        else:
            assert "remote_address=self.sock.getpeername()," in source

    niquests_root = Path(root) / tmp_dir / "niquests"
    niquests_pyproject = niquests_root / "pyproject.toml"
    niquests_metadata = niquests_pyproject.read_text(encoding="utf-8")
    urllib3_requirement = "urllib3.future>=2.13.903,<3"
    assert urllib3_requirement in niquests_metadata
    niquests_pyproject.write_text(
        niquests_metadata.replace(
            urllib3_requirement,
            f"urllib3-future @ {urllib3_root.resolve().as_uri()}",
        )
        .replace('"urllib3.future[socks]"', '"python-socks>=2,<=2.8.1"')
        .replace('"urllib3.future[ws]"', '"wsproto>=1.2,<2"')
        + "\n[tool.hatch.metadata]\nallow-direct-references = true\n",
        encoding="utf-8",
    )

    session.chdir("niquests")

    session.run("git", "rev-parse", "HEAD", external=True)
    session.install("nox")

    constraint = Path(root) / tmp_dir / "qh3-constraint.txt"
    constraint.write_text(
        f"qh3 @ {Path(root).resolve().as_uri()}\n",
        encoding="utf-8",
    )
    nested_session = f"test-{sys.version_info.major}.{sys.version_info.minor}"
    session.run(
        "nox",
        "-s",
        nested_session,
        *(("--", *session.posargs) if session.posargs else ()),
        env={
            "NIQUESTS_STRICT_OCSP": "1",
            "PIP_CONSTRAINT": str(constraint),
        },
    )


@nox.session()
def format(session: nox.Session) -> None:
    """Run code formatters."""
    lint(session)


@nox.session
def lint(session: nox.Session) -> None:
    session.install("pre-commit")
    session.run("pre-commit", "run", "--all-files")


@nox.session
def docs(session: nox.Session) -> None:
    """Build the documentation with the same strict settings as Read the Docs."""
    session.install("-r", "docs/docs-requirements.txt")
    session.run("zensical", "build", "--clean", "--strict")
