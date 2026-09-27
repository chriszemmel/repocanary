import subprocess

from setuptools import setup, find_packages
from setuptools.command.build_ext import build_ext


def git_version():
    try:
        return subprocess.check_output(["git", "describe", "--tags"]).decode().strip()
    except (OSError, subprocess.CalledProcessError):
        return "0.0.0"


class BuildExt(build_ext):
    def build_extensions(self):
        build_ext.build_extensions(self)


setup(
    name="greeting",
    version=git_version(),
    packages=find_packages(),
    cmdclass={"build_ext": BuildExt},
)
