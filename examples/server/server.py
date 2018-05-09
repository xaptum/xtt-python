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

def main(loop=True):
    bind_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    bind_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bind_socket.bind(("localhost", 4444))
    bind_socket.listen(10)

    print("XTT server listening on port", bind_socket.getsockname()[1])

    cert     = xtt.ED25519ServerCertificate.from_file("server_certificate.bin")
    key      = xtt.ED25519PrivateKey.from_file("server_privatekey.bin")
    cert_ctx = xtt.ServerED25519CertificateContext(cert, key)

    group_gpk      = xtt.LRSWGroupPublicKey.from_file("daa_gpk.bin")
    group_id       = hashlib.sha256(group_gpk.data).digest()
    group_basename = b'BASENAME'
    group_ctx      = xtt.LRSWGroupPublicKeyContext(group_gpk, group_basename)
    def group_from_id(id):
        if id.data == group_id:
            return group_ctx
        else:
            return None

    def assign_client_id(requested, group_id, pseudonym):
        # Hash the group_id and pseudonym to make up an ID
        hash = hashlib.sha256()
        hash.update(group_id.data)
        hash.update(pseudonym.data)
        id_raw = hash.digest()[:16]
        id_hex = hash.hexdigest()[:32]
        print("Assigning identity", id_hex)
        return xtt.Identity(id_raw)

    while loop:
        try:
            new_socket, from_addr = bind_socket.accept()

            try:
                xtt_socket = xtt.XTTServerSocket(new_socket, cert_ctx, group_from_id, assign_client_id)
                print("Starting handshake...")
                xtt_socket.handle_connect()
                new_socket.close()
                print("Handshake succeeded.")
            except Exception as e:
                print("Handshake failed.")
                traceback.print(e)
            finally:
                new_socket.close()
                xtt_socket = None

        except KeyboardInterrupt:
            print()
            break

    bind_socket.close()

if __name__ == "__main__":
    main()
