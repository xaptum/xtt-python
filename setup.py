#!/usr/bin/env python

import os
import sys
from setuptools import setup, find_packages
from setuptools.command.build_ext import build_ext
from _build_xtt import build_all, XTT

VERSION = '{}-0'.format(XTT.version[1:])

def _requirements(filepath):
    with open(filepath, 'rt') as f:
        reqs = f.read().splitlines()
        return [r for r in reqs if not r.strip().startswith('#')]

class cffiBuilder(build_ext, object):

    def build_extension(self, ext):
        """
         Compile XTT and the extension
        """
        build_all()
        super(cffiBuilder, self).build_extension(ext)

setup(
    name = 'xtt',
    version = VERSION,
    description = 'Python wrapper for the XTT Trust Transit protocol securing IoT network traffic.',
    long_description = open('README.md', 'rt').read(),
    author = 'Xaptum, Inc.',
    author_email = 'tech@xaptum.com',
    license = 'Apache 2.0',
    url = 'https://github.com/xaptum/xtt-python',
    download_url = 'https://github.com/xaptum/xtt-python/{}.tar.gz'.format(VERSION),

    packages = ['xtt', 'xtt.crypto', 'xtt.test'],

    zip_safe=False,
    cffi_modules = ['_build_ffi.py:ffi'],

    keywords = ['xtt', 'security', 'cryptography', 'IoT', 'Xaptum'],
    classifiers=[
        u'Development Status :: 5 - Production/Stable',
        u'Intended Audience :: Developers',
        u'License :: OSI Approved :: Apache Software License',
        u'Programming Language :: Python :: 2.7'
        u'Programming Language :: Python :: 3.4'
        u'Programming Language :: Python :: 3.5'
        u'Programming Language :: Python :: 3.6'
        u'Topic :: Security',
        u'Topic :: Security :: Cryptography',
        u'Topic :: Software Development'
    ],

    install_requires = _requirements("requirements/prod.txt"),
    setup_requires = _requirements("requirements/setup.txt"),
    tests_require = _requirements("requirements/test.txt"),
    test_suite = 'nose.collector',
    cmdclass={'build_ext' : cffiBuilder}
)
