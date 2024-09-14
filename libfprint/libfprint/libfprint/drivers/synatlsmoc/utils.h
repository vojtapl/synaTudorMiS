#pragma once

#include <glib.h>
#include <openssl/decoder.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/param_build.h>

G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_CIPHER_CTX, EVP_CIPHER_CTX_free);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_KDF, EVP_KDF_free);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_KDF_CTX, EVP_KDF_CTX_free);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_MD_CTX, EVP_MD_CTX_free);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_PKEY_CTX, EVP_PKEY_CTX_free);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_PKEY, EVP_PKEY_free);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(OSSL_PARAM_BLD, OSSL_PARAM_BLD_free);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(OSSL_PARAM, OSSL_PARAM_free);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(OSSL_DECODER_CTX, OSSL_DECODER_CTX_free);

gchar *bin2hex(const guint8 *arr, const gsize size);
const char *status_to_str(guint16 status);
const char *cmd_to_str(guint8 cmd);
const char *event_type_to_str(guint8 event_type);
const char *obj_type_to_str(guint8 obj_type);
void reverse_array(guint8 *arr, gsize size);
