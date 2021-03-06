# xtt-python

[![PyPI version](https://badge.fury.io/py/xtt.svg)](https://badge.fury.io/py/xtt)
[![Build Status](https://travis-ci.org/xaptum/xtt-python.svg?branch=master)](https://travis-ci.org/xaptum/xtt-python)

A Python module (`xtt`) that encapsulates the [XTT Trusted
Transit](https://github.com/xaptum/xtt) protocol for securing Internet
of Things (IoT) devices.

## Installation

``` bash
pip install xtt
```

The package is published to PyPI for Python 2.7 and 3.3+ for Linux and
OS X. `pip` installs all dependencies, including `xtt` itself.

## Quick-Start

``` python
import socket
import xtt

# In these examples, we assume the id, certs, and keys needed to run
# an XTT client handshake are available as files.

# Load root certificate, used to authenticate the server
root_id     = xtt.CertificateRootId.from_file("root_id.bin")
root_pubkey = xtt.ED25519PublicKey.from_file("root_pub.bin")

# Load the server id
server_id   = xtt.Identity.from_file("server_id.bin")

# Load the DAA group information
group_basename  = b'BASENAME'
group_gpk       = xtt.LRSWGroupPublicKey.from_file("daa_gpk.bin")
group_id        = xtt.GroupId(hashlib.sha256(group_gpk.data).digest())
group_cred      = xtt.LRSWCredential.from_file("daa_cred.bin")
group_secretkey = xtt.LRSWPrivateKey.from_file("daa_secretkey.bin")
group_ctx       = xtt.ClientLRSWGroupContext(group_id, group_secretkey,
                                             group_cred, group_basename)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
sock.connect(('192.0.2.1', 4443))

xtt_sock = xtt.XTTClientSocket(sock,
                               version = xtt.Version.ONE,
                               suite_spec = xtt.SuiteSpec.XTT_X25519_LRSW_ED25519_CHACHA20POLY1305_SHA512,
                               group_ctx, server_id, root_id, root_pubkey)
xtt_sock.start()
my_identity    = xtt_sock.identity
my_public_key  = xtt_sock.longterm_public_key
my_private_key = xtt_sock.longterm_private_key
```

## Contributing

Please submit bugs, questions, suggestions, or (ideally) contributions
as issues and pull requests on GitHub.

## License
Copyright 2018 Xaptum, Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not
use this work except in compliance with the License. You may obtain a copy of
the License from the LICENSE.txt file or at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations under
the License.
