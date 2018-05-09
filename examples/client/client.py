from __future__ import absolute_import
from __future__ import print_function

import argparse
import hashlib
import sys
import socket
import traceback

try:
    import xtt
except ImportError as e:
    print(e)
    print("You must run 'python setup.py install' to use the examples")
    sys.exit()

def main():
    root_id     = xtt.CertificateRootId.from_file("root_id.bin")
    root_pubkey = xtt.ED25519PublicKey.from_file("root_pub.bin")

    server_id   = xtt.Identity.from_file("server_id.bin")

    group_basename  = b'BASENAME'
    group_gpk       = xtt.LRSWGroupPublicKey.from_file("daa_gpk.bin")
    group_id        = xtt.GroupId(hashlib.sha256(group_gpk.data).digest())
    group_cred      = xtt.LRSWCredential.from_file("daa_cred.bin")
    group_secretkey = xtt.LRSWPrivateKey.from_file("daa_secretkey.bin")
    group_ctx       = xtt.ClientLRSWGroupContext(group_id, group_secretkey,
                                                 group_cred, group_basename)

    version         = xtt.Version.ONE
    suite_spec      = xtt.SuiteSpec.XTT_X25519_LRSW_ED25519_CHACHA20POLY1305_SHA512

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    sock.connect(("localhost", 4444))

    try:
        xtt_sock = xtt.XTTClientSocket(sock, version, suite_spec, group_ctx,
                                       server_id, root_id, root_pubkey)
        print("Starting handshake...")
        xtt_sock.start()
        print("Received identity", xtt_sock.identity)
        print("Handshake succeeded.")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
