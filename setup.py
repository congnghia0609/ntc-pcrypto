#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Note: To use the 'upload' functionality of this file, you must:
#   $ pip install twine

import os
import sys
from shutil import rmtree
from setuptools import find_packages, setup, Command
from setuptools.command.test import test as TestCommand

# Package meta-data.
NAME = 'ntc-pcrypto'
VERSION = '0.2.0'
DESCRIPTION = 'ntc-pcrypto is a module python cryptography'
# LONG_DESCRIPTION = 'ntc-pcrypto is a module python cryptography'
with open("README.md", "r") as fh:
    LONG_DESCRIPTION = fh.read()
URL = 'https://github.com/congnghia0609/ntc-pcrypto'
EMAIL = 'congnghia0609@gmail.com'
AUTHOR = 'NghiaTC'

# What packages are required for this module to be executed?
REQUIRED = [
]
TEST_REQUIRED = [
    'pep8',
    'pytest',
    'pytest-pylint ; python_version >= "3.4.0"',
    'pytest-xdist',
    'pytest-runner',
    'pytest-pep8',
    'pytest-cov',
    'yapf',
    'autopep8'
]

BUILD_REQUIRED = [
    'twine',
    'pypandoc',
    'recommonmark'
    'wheel',
    'setuptools',
    'sphinx',
    'sphinx_rtd_theme'
]
# The rest you shouldn't have to touch too much :)
# ------------------------------------------------
# Except, perhaps the License and Trove Classifiers!
# If you do change the License, remember to change the Trove Classifier for that!

here = os.path.abspath(os.path.dirname(__file__))


# Import the README and use it as the long-description.
# Note: this will only work if 'README.rst' is present in your MANIFEST.in file!
# with io.open(os.path.join(here, 'README.rst'), encoding='utf-8') as f:
#     long_description = '\n' + f.read()


class PyTest(TestCommand):
    user_options = [('pytest-args=', 'a', "Arguments to pass into py.tests")]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        try:
            from multiprocessing import cpu_count
            self.pytest_args = ['-n', str(cpu_count()), '--boxed']
        except (ImportError, NotImplementedError):
            self.pytest_args = ['-n', '1', '--boxed']

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        import pytest

        errno = pytest.main(self.pytest_args)
        sys.exit(errno)


class UploadCommand(Command):
    """Support setup.py upload."""

    description = 'Build and publish the package.'
    user_options = []

    @staticmethod
    def status(s):
        """Prints things in bold."""
        print('\033[1m{0}\033[0m'.format(s))

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        try:
            self.status('Removing previous builds…')
            rmtree(os.path.join(here, 'dist'))
        except OSError:
            pass

        self.status('Building Source and Wheel (universal) distribution…')
        os.system('{0} setup.py sdist bdist_wheel --universal'.format(sys.executable))

        self.status('Uploading the package to PyPi via Twine…')
        os.system('twine upload dist/*')

        sys.exit()


# Where the magic happens:
setup(
    name=NAME,
    version=VERSION,
    description=DESCRIPTION,
    keywords=['ntc-pcrypto', 'pcrypto', 'cryptography', 'crypto', 'encrypt'],
    long_description=LONG_DESCRIPTION,
    long_description_content_type='text/markdown',
    author=AUTHOR,
    author_email=EMAIL,
    url=URL,
    # packages=find_packages(),
    packages=find_packages(exclude=('tests', 'scripts')),
    # packages=find_packages(exclude=('scripts')),
    # entry_points={
    #         'console_scripts': [],
    # },
    install_requires=REQUIRED,
    extras_require={
        'dev': TEST_REQUIRED + BUILD_REQUIRED,
        'build': BUILD_REQUIRED,
        'test': TEST_REQUIRED
    },
    tests_require=TEST_REQUIRED,
    include_package_data=True,
    license='Apache License 2.0',

    classifiers=[
        # Trove classifiers
        # Full list: https://pypi.python.org/pypi?%3Aaction=list_classifiers
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Natural Language :: English', 'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Development Status :: 4 - Beta'
    ],
    # $ setup.py publish support.
    cmdclass={
        'upload': UploadCommand,
        'test': PyTest
    },
)
