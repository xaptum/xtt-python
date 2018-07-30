# Copyright 2018 Xaptum, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License

import os
import multiprocessing as mp
import subprocess
from contextlib import contextmanager
from distutils.util import get_platform


# Note: Reset POST to 0 on version bump
XTT_VERSION = 'v0.9.2'
POST        = '0'
VERSION     = XTT_VERSION[1:] + '-' + POST

@contextmanager
def chdir(new_path, mkdir=False):
    old_path = os.getcwd()

    if mkdir:
        try:
            os.mkdir(new_path)
        except OSError:
            pass

    try:
        yield os.chdir(new_path)
    finally:
        os.chdir(old_path)

def local_path(path):
    """
    Return the absolute path relative to the root of this project
    """
    current = os.path.dirname(__file__)
    root = current
    return os.path.abspath(os.path.join(root, path))

class Library(object):
    """
    Configuration for downloading and building a libary locally
    """

    def __init__(self, name, version, git_addr, flags, targets, env={}):
        self.name     = name
        self.version  = version
        self.git_addr = git_addr
        self.flags    = flags
        self.targets  = targets
        self.env      = os.environ
        for k, v in env.items():
            self.env[k] = v

    @property
    def src_path(self):
        path = "build/lib/{}/src".format(self.name)
        return local_path(path)

    @property
    def install_prefix(self):
        return local_path("build/lib/{}/{}/{}".format(
            self.name, get_platform(), self.version))

    @property
    def include_path(self):
        return os.path.join(self.install_prefix, "include")

    @property
    def libs(self):
        return [t.split('.', 1)[0][3:] for t in self.targets]

    def build(self):
        if not os.path.isdir(self.src_path):
            self.clone()
            rebuild = True
        else:
            rebuild = self.checkout()

        libfiles = (os.path.join(self.lib_path, lib) for lib in self.targets)
        if rebuild or any(not os.path.isfile(f) for f in libfiles):
            self.make()

    def call(self, cmd):
        subprocess.check_call(cmd, shell=True, env=self.env)

    def clone(self):
        self.call("git clone --depth=1 --branch={} {} {}".format(
            self.version, self.git_addr, self.src_path))

    def checkout(self):
        with chdir(self.src_path):
            current = subprocess.check_output(
                ["git", "describe", "--all", "--exact-match"]
            ).strip().decode().split("/")[-1]

            if current != self.version:
                tags = subprocess.check_output(
                    ["git", "tag"]
                ).strip().decode().split("\n")

                if self.version != "master" and self.version not in tags:
                    self.call("git fetch --depth=1 origin tag {}".format(self.version))

                self.call("git checkout --force {}".format(self.version))
                return True

        return False

class CMakeLibrary(Library):

    @property
    def config_path(self):
        return os.path.join(self.lib_path, "cmake", self.name)

    @property
    def lib_path(self):
        if "linux-x86_64" in self.install_prefix:
            libdir = "lib64"
        else:
            libdir = "lib"
        return os.path.join(self.install_prefix, libdir)

    def make(self):
        flags = self.flags
        flags.append('-DCMAKE_BUILD_TYPE=Release')
        flags.append('-DCMAKE_INSTALL_PREFIX={}'.format(self.install_prefix))
        flags.append('-DCMAKE_POSITION_INDEPENDENT_CODE=ON')
        flags.append('-DBUILD_STATIC_LIBS=ON')
        flags.append('-DBUILD_SHARED_LIBS=OFF')
        flags.append('-DBUILD_EXAMPLES=OFF')
        flags.append('-DBUILD_TESTING=OFF')

        with chdir(self.src_path):
            self.call("git clean -fdX")

            with chdir("build", mkdir=True):
                self.call("cmake .. {}".format(" ".join(flags)))
                self.call("make -j {}".format(mp.cpu_count()))
                self.call("make install")

class AutotoolsLibrary(Library):

    @property
    def config_path(self):
        return os.path.join(self.lib_path, "pkgconfig")

    @property
    def lib_path(self):
        return os.path.join(self.install_prefix, "lib")

    def make(self):
        flags = self.flags
        flags.append('--prefix={}'.format(self.install_prefix))
        flags.append('--disable-shared')
        flags.append('--disable-pie') # https://github.com/jedisct1/libsodium/issues/292
#        flags.append('CFLAGS=-fPIC')

        with chdir(self.src_path):
            self.call("git clean -fdX")

            self.call("./autogen.sh")
            self.call("./configure {}".format(" ".join(flags)))
            self.call("make -j {}".format(mp.cpu_count()))
            self.call("make install")

AMCL = CMakeLibrary('amcl', '4.7.3',  'https://github.com/milagro-crypto/milagro-crypto-c.git',
                    [
                        '-DAMCL_INCLUDE_SUBDIR=amcl',
                        '-DAMCL_CURVE=FP256BN,NIST256',
                        '-DAMCL_RSA=',
                        '-DBUILD_BENCHMARKS=OFF',
                        '-DBUILD_DOCS=OFF',
                        '-DBUILD_PYTHON=OFF',
                        '-DBUILD_MPIN=OFF',
                        '-DBUILD_WCC=OFF',
                        '-DBUILD_X509=OFF'
                    ],
                    [
                        'libamcl_curve_NIST256.a',
                        'libamcl_curve_FP256BN.a',
                        'libamcl_pairing_FP256BN.a',
                        'libamcl_core.a',
                    ])

ECDAA  = CMakeLibrary('ecdaa', 'v0.9.1', 'https://github.com/xaptum/ecdaa.git',
                      [
                          '-DECDAA_CURVES=FP256BN',
                          '-DECDAA_TPM_SUPPORT=OFF',
                          '-DAMCL_DIR={}'.format(AMCL.config_path)
                      ],
                      [
                          'libecdaa.a'
                      ])

SODIUM = AutotoolsLibrary('libsodium', '1.0.16', 'https://github.com/jedisct1/libsodium.git',
                          [
                              '--disable-debug',
                              '--disable-dependency-tracking'
                          ],
                          [
                              'libsodium.a'
                          ])

XTT = CMakeLibrary('xtt', XTT_VERSION, 'https://github.com/xaptum/xtt.git',
                   [
                       '-DUSE_TPM=OFF',
                       '-Dsodium_USE_STATIC_LIBS=ON',
                       '-DAMCL_DIR={}'.format(AMCL.config_path),
                       '-Decdaa_DIR={}'.format(ECDAA.config_path)
                   ],
                   [
                       'libxtt.a'
                   ],
                   {
                       'PKG_CONFIG_PATH' : SODIUM.config_path
                   })

def build_all():
    AMCL.build()
    ECDAA.build()
    SODIUM.build()
    XTT.build()
