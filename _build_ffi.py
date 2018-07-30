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

from cffi import FFI
from _build_xtt import AMCL, ECDAA, SODIUM, XTT

ffi = FFI()

print("ECDAA lib path:", ECDAA.lib_path)

ffi.set_source(
    "xtt._ffi",
    """
    #include <xtt.h>
    """,
    include_dirs=[XTT.include_path],
    library_dirs=[AMCL.lib_path,
                  ECDAA.lib_path,
                  SODIUM.lib_path,
                  XTT.lib_path],
    libraries = ["c"] + XTT.libs + ECDAA.libs + AMCL.libs + SODIUM.libs
)

ffi.cdef(
    """
    /**
     * Return Codes
     */
    typedef enum {
        XTT_RETURN_SUCCESS = 0,

        // Next-state codes:
        XTT_RETURN_WANT_WRITE,
        XTT_RETURN_WANT_READ,
        XTT_RETURN_WANT_BUILDSERVERATTEST,
        XTT_RETURN_WANT_PREPARSESERVERATTEST,
        XTT_RETURN_WANT_BUILDIDCLIENTATTEST,
        XTT_RETURN_WANT_PREPARSEIDCLIENTATTEST,
        XTT_RETURN_WANT_VERIFYGROUPSIGNATURE,
        XTT_RETURN_WANT_BUILDIDSERVERFINISHED,
        XTT_RETURN_WANT_PARSEIDSERVERFINISHED,
        XTT_RETURN_HANDSHAKE_FINISHED,

        // Error codes:
        XTT_RETURN_RECEIVED_ERROR_MSG,

        XTT_RETURN_BAD_INIT,
        XTT_RETURN_BAD_IO,
        XTT_RETURN_BAD_HANDSHAKE_ORDER,
        XTT_RETURN_INSUFFICIENT_ENTROPY,
        XTT_RETURN_BAD_IO_LENGTH,
        XTT_RETURN_UINT16_OVERFLOW,
        XTT_RETURN_UINT32_OVERFLOW,
        XTT_RETURN_NULL_BUFFER,
        XTT_RETURN_INCORRECT_TYPE,
        XTT_RETURN_DIFFIE_HELLMAN,
        XTT_RETURN_UNKNOWN_VERSION,
        XTT_RETURN_UNKNOWN_SUITE_SPEC,
        XTT_RETURN_INCORRECT_LENGTH,
        XTT_RETURN_BAD_CLIENT_SIGNATURE,
        XTT_RETURN_BAD_SERVER_SIGNATURE,
        XTT_RETURN_BAD_ROOT_SIGNATURE,
        XTT_RETURN_UNKNOWN_CRYPTO_SPEC,
        XTT_RETURN_BAD_CERTIFICATE,
        XTT_RETURN_UNKNOWN_CERTIFICATE,
        XTT_RETURN_UNKNOWN_GID,
        XTT_RETURN_BAD_GPK,
        XTT_RETURN_BAD_ID,
        XTT_RETURN_BAD_EXPIRY,
        XTT_RETURN_CRYPTO,
        XTT_RETURN_DAA,
        XTT_RETURN_BAD_COOKIE,
        XTT_RETURN_COOKIE_ROTATION,
        XTT_RETURN_RECORD_FAILED_CRYPTO,
        XTT_RETURN_BAD_FINISH,
        XTT_RETURN_CONTEXT_BUFFER_OVERFLOW
    } xtt_return_code_type;

    const char* xtt_strerror(xtt_return_code_type rc);

    /**
     * Crypto Types
     */
    typedef enum {
        XTT_VERSION_ONE = 0x01
    } xtt_version;

    typedef enum {
        XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512    = 0x0001,
        XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B   = 0x0002,
        XTT_X25519_LRSW_ECDSAP256_AES256GCM_SHA512           = 0x0003,
        XTT_X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B          = 0x0004,
    } xtt_suite_spec;

    typedef enum {
        XTT_SERVER_SIGNATURE_TYPE_ECDSAP256 = 1,
    } xtt_server_signature_type;

    typedef struct {unsigned char data[16];} xtt_identity_type;

    typedef struct {unsigned char data[32];} xtt_group_id;

    typedef struct {unsigned char data[260];} xtt_daa_credential_lrsw;
    typedef struct {unsigned char data[32];} xtt_daa_priv_key_lrsw;
    typedef struct {unsigned char data[258];} xtt_daa_group_pub_key_lrsw;
    typedef struct {unsigned char data[65];} xtt_daa_pseudonym_lrsw;

    typedef struct {unsigned char data[16];} xtt_certificate_root_id;
    typedef struct {char data[8];} xtt_certificate_expiry;

    typedef struct {unsigned char data[65];} xtt_ecdsap256_pub_key;
    typedef struct {unsigned char data[32];} xtt_ecdsap256_priv_key;

    /**
     * Crypto Wrapper
     */
    int
    xtt_crypto_create_ecdsap256_key_pair(xtt_ecdsap256_pub_key *pub_key,
                                         xtt_ecdsap256_priv_key *priv_key);

    /**
     * ASN1
     */
    size_t xtt_x509_certificate_length(void);
    size_t xtt_asn1_private_key_length(void);

    int
    xtt_x509_from_ecdsap256_keypair(const xtt_ecdsap256_pub_key *pub_key_in,
                                    const xtt_ecdsap256_priv_key *priv_key_in,
                                    const xtt_identity_type *common_name,
                                    unsigned char *certificate_out,
                                    size_t certificate_out_length);

    int xtt_asn1_from_ecdsap256_private_key(const xtt_ecdsap256_priv_key *priv_key_in,
                                            const xtt_ecdsap256_pub_key *pub_key_in,
                                            unsigned char *asn1_out,
                                            size_t asn1_out_length);

    /**
     * Certificates
     */
    struct xtt_server_certificate_raw_type;

    xtt_return_code_type
    xtt_generate_server_certificate_ecdsap256(unsigned char *cert_out,
                                              xtt_identity_type *servers_id,
                                              xtt_ecdsap256_pub_key *servers_pub_key,
                                              xtt_certificate_expiry *expiry,
                                              xtt_certificate_root_id *roots_id,
                                              xtt_ecdsap256_priv_key *roots_priv_key);

    uint16_t
    xtt_server_certificate_length(xtt_suite_spec suite_spec);

    uint16_t
    xtt_server_certificate_length_fromsignaturetype(xtt_server_signature_type type);

    unsigned char*
    xtt_server_certificate_access_id(const struct xtt_server_certificate_raw_type *certificate);

    unsigned char*
    xtt_server_certificate_access_expiry(const struct xtt_server_certificate_raw_type *certificate);

    unsigned char*
    xtt_server_certificate_access_rootid(const struct xtt_server_certificate_raw_type *certificate);

    unsigned char*
    xtt_server_certificate_access_pubkey(const struct xtt_server_certificate_raw_type *certificate);

    unsigned char*
    xtt_server_certificate_access_rootsignature(const struct xtt_server_certificate_raw_type *certificate,
                                                xtt_suite_spec suite_spec);

    /**
     * Context
     */
    struct xtt_server_handshake_context {
        ...;
    };

    struct xtt_client_handshake_context {
        ...;
    };

    struct xtt_server_cookie_context {
        ...;
    };

    struct xtt_server_certificate_context {
        ...;
    };

    struct xtt_server_root_certificate_context {
        ...;
    };

    struct xtt_group_public_key_context {
        ...;
    };

    struct xtt_client_group_context {
        ...;
    };

    xtt_return_code_type
    xtt_initialize_server_handshake_context(struct xtt_server_handshake_context* ctx_out,
                                            unsigned char *in_buffer,
                                            uint16_t in_buffer_size,
                                            unsigned char *out_buffer,
                                            uint16_t out_buffer_size);

    xtt_return_code_type
    xtt_initialize_client_handshake_context(struct xtt_client_handshake_context* ctx_out,
                                            unsigned char *in_buffer,
                                            uint16_t in_buffer_size,
                                            unsigned char *out_buffer,
                                            uint16_t out_buffer_size,
                                            xtt_version version,
                                            xtt_suite_spec suite_spec);

    xtt_return_code_type
    xtt_initialize_server_cookie_context(struct xtt_server_cookie_context* ctx);

    xtt_return_code_type
    xtt_initialize_server_certificate_context_ecdsap256(struct xtt_server_certificate_context *ctx_out,
                                                        const unsigned char *serialized_certificate,
                                                        const xtt_ecdsap256_priv_key *private_key);

    xtt_return_code_type
    xtt_initialize_server_root_certificate_context_ecdsap256(struct xtt_server_root_certificate_context *cert_out,
                                                             xtt_certificate_root_id *id,
                                                             xtt_ecdsap256_pub_key *public_key);

    xtt_return_code_type
    xtt_initialize_group_public_key_context_lrsw(struct xtt_group_public_key_context *ctx_out,
                                                 const unsigned char *basename,
                                                 uint16_t basename_length,
                                                 const xtt_daa_group_pub_key_lrsw *gpk);

    xtt_return_code_type
    xtt_initialize_client_group_context_lrsw(struct xtt_client_group_context *ctx_out,
                                             xtt_group_id *gid,
                                             xtt_daa_priv_key_lrsw *priv_key,
                                             xtt_daa_credential_lrsw *cred,
                                             const unsigned char *basename,
                                             uint16_t basename_length);

    xtt_return_code_type
    xtt_get_version(xtt_version *version_out,
                    const struct xtt_server_handshake_context *handshake_context);

    xtt_return_code_type
    xtt_get_suite_spec(xtt_suite_spec *suite_spec_out,
                       const struct xtt_server_handshake_context *handshake_context);

    xtt_return_code_type
    xtt_get_clients_longterm_key_ecdsap256(xtt_ecdsap256_pub_key *longterm_key_out,
                                           const struct xtt_server_handshake_context *handshake_context);

    xtt_return_code_type
    xtt_get_clients_identity(xtt_identity_type *client_id_out,
                             const struct xtt_server_handshake_context *handshake_context);

    xtt_return_code_type
    xtt_get_clients_pseudonym_lrsw(xtt_daa_pseudonym_lrsw *pseudonym_out,
                                   const struct xtt_server_handshake_context *handshake_context);

    xtt_return_code_type
    xtt_get_my_longterm_key_ecdsap256(xtt_ecdsap256_pub_key *longterm_key_out,
                                      const struct xtt_client_handshake_context *handshake_context);

    xtt_return_code_type
    xtt_get_my_longterm_private_key_ecdsap256(xtt_ecdsap256_priv_key *longterm_key_priv_out,
                                              const struct xtt_client_handshake_context *handshake_context);

    xtt_return_code_type
    xtt_get_my_identity(xtt_identity_type *client_id_out,
                        const struct xtt_client_handshake_context *handshake_context);

    xtt_return_code_type
    xtt_get_my_pseudonym_lrsw(xtt_daa_pseudonym_lrsw *pseudonym_out,
                              const struct xtt_client_handshake_context *handshake_context);

    /**
     * Messages
     */
    uint16_t max_handshake_server_message_length(void);
    uint16_t max_handshake_client_message_length(void);

    xtt_return_code_type
    xtt_handshake_client_handle_io(uint16_t bytes_written,
                                   uint16_t bytes_read,
                                   uint16_t *io_bytes_requested,
                                   unsigned char **io_ptr,
                                   struct xtt_client_handshake_context* ctx);

    xtt_return_code_type
    xtt_handshake_client_start(uint16_t *io_bytes_requested,
                               unsigned char **io_ptr,
                               struct xtt_client_handshake_context* ctx);

    xtt_return_code_type
    xtt_handshake_client_preparse_serverattest(xtt_certificate_root_id *claimed_root_out,
                                               uint16_t *io_bytes_requested,
                                               unsigned char **io_ptr,
                                               struct xtt_client_handshake_context* handshake_ctx);


    xtt_return_code_type
    xtt_handshake_client_build_idclientattest(uint16_t *io_bytes_requested,
                                              unsigned char **io_ptr,
                                              const struct xtt_server_root_certificate_context* root_server_certificate,
                                              const xtt_identity_type* requested_client_id,
                                              const xtt_identity_type* intended_server_id,
                                              struct xtt_client_group_context* group_ctx,
                                              struct xtt_client_handshake_context* handshake_ctx);

    xtt_return_code_type
    xtt_handshake_client_parse_idserverfinished(uint16_t *io_bytes_requested,
                                                unsigned char **io_ptr,
                                                struct xtt_client_handshake_context* handshake_ctx);

    xtt_return_code_type
    xtt_handshake_server_handle_io(uint16_t bytes_written,
                                   uint16_t bytes_read,
                                   uint16_t *io_bytes_requested,
                                   unsigned char **io_ptr,
                                   struct xtt_server_handshake_context* ctx);

    xtt_return_code_type
    xtt_handshake_server_handle_connect(uint16_t *io_bytes_requested,
                                        unsigned char **io_ptr,
                                        struct xtt_server_handshake_context* ctx);

    xtt_return_code_type
    xtt_handshake_server_build_serverattest(uint16_t *io_bytes_requested,
                                            unsigned char **io_ptr,
                                            struct xtt_server_handshake_context* ctx,
                                            const struct xtt_server_certificate_context* certificate_ctx,
                                            struct xtt_server_cookie_context* cookie_ctx);

    xtt_return_code_type
    xtt_handshake_server_preparse_idclientattest(uint16_t *io_bytes_requested,
                                                 unsigned char **io_ptr,
                                                 xtt_identity_type* requested_client_id_out,
                                                 xtt_group_id* claimed_group_id_out,
                                                 struct xtt_server_cookie_context* cookie_ctx,
                                                 struct xtt_server_certificate_context *certificate_ctx,
                                                 struct xtt_server_handshake_context* handshake_ctx);

    xtt_return_code_type
    xtt_handshake_server_verify_groupsignature(uint16_t *io_bytes_requested,
                                               unsigned char **io_ptr,
                                               struct xtt_group_public_key_context* group_pub_key_ctx,
                                               struct xtt_server_certificate_context *certificate_ctx,
                                               struct xtt_server_handshake_context* handshake_ctx);

    xtt_return_code_type
    xtt_handshake_server_build_idserverfinished(uint16_t *io_bytes_requested,
                                                unsigned char **io_ptr,
                                                xtt_identity_type *client_id,
                                                struct xtt_server_handshake_context* handshake_ctx);
    """
)

if __name__ == "__main__":
    ffi.compile(verbose=True)
