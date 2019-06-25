/* Copyright (c) 2019 by Erik Larsson 
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#include <tss2/tss2_esys.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <stdlib.h>
#include <string.h>
#include "agent.h"


void dumpmessage(buffer_t *msg) {
  int i;
  for (i=0;i < msg->len;i++) {
    printf("\\x%02x", msg->data[i]);
  }
  printf("\n");
}

const EVP_MD *hash_alg_to_evp(TPM2_ALG_ID alg) {
  switch (alg) {
  case TPM2_ALG_SHA1:
    return EVP_sha1();
  case TPM2_ALG_SHA256:
    return EVP_sha256();
  case TPM2_ALG_SHA384:
    return EVP_sha384();
  case TPM2_ALG_SHA512:
    return EVP_sha512();
  }
  
  return NULL;
}

int hash(const EVP_MD *type, TPM2B_DIGEST *dig, uint8_t *data, size_t len) {
  int r;
  unsigned int mdsize;
  EVP_MD_CTX *mdctx = NULL;

  mdctx = EVP_MD_CTX_new();
  if (!mdctx) {
    return -1;
  }

  r = EVP_DigestInit(mdctx, type);
  if (r != 1) {
    r = -1;
    goto out;
  }

  r = EVP_DigestUpdate(mdctx, data, len);
  if (r != 1) {
    r = -1;
    goto out;
  }

  r = EVP_DigestFinal(mdctx, dig->buffer, &mdsize);
  if (r != 1) {
    r = -1;
    goto out;
  }

  dig->size = mdsize;

 out:
  EVP_MD_CTX_free(mdctx);  
  return r;
}

TPM2_ALG_ID flag_to_hash_alg(uint32_t flags) {
  switch (flags & 0x07) {
  case 0:
    return TPM2_ALG_SHA1;
  case SSH_AGENT_RSA_SHA2_256:
    return TPM2_ALG_SHA256;
  case SSH_AGENT_RSA_SHA2_512:
    return TPM2_ALG_SHA512;
  }

  return TPM2_ALG_NULL;
}

const char *rsa_hash_alg_to_string(TPM2_ALG_ID alg) {
  switch (alg) {
  case TPM2_ALG_SHA1:
    return "ssh-rsa";
  case TPM2_ALG_SHA256:
    return "rsa-sha2-256";
  case TPM2_ALG_SHA512:
    return "rsa-sha2-512";    
  }
  
  return NULL;
}

int append_digestinfo(buffer_t *buf, TPM2_ALG_ID alg, TPM2B_DIGEST *digest) {
  int r;
  
  static uint8_t oid_sha1[] =
    { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03,
      0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 };
  static uint8_t oid_sha256[] =
    { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
      0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };
  static uint8_t oid_sha512[] =
    { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
      0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 };

  switch (alg) {
  case TPM2_ALG_SHA1:
    r = append_buffer(buf, oid_sha1, sizeof(oid_sha1));
    break;
  case TPM2_ALG_SHA256:
    r = append_buffer(buf, oid_sha256, sizeof(oid_sha256));
    break;
  case TPM2_ALG_SHA512:
    r = append_buffer(buf, oid_sha512, sizeof(oid_sha512));
    break;
  default:
    return -1;
  }

  if (r) {
    return r;
  }

  r = append_buffer(buf, digest->buffer, digest->size);

  return r;
}

int add_padding(TPM2B_PUBLIC_KEY_RSA *msg, buffer_t *diginfo) {
  int p, pssize;
  
  msg->buffer[0] = 0;
  msg->buffer[1] = 1;
  p = 2;
  
  pssize = msg->size - diginfo->len - 3;
  memset(msg->buffer + p, 0xFF, pssize);
  p = p + pssize;
  
  msg->buffer[p] = 0;
  p++;

  memcpy(msg->buffer + p, diginfo->data, diginfo->len);
  
  return 0;
}

int sign_rsa(ESYS_CONTEXT *ctx, tpm_key_t *key, uint32_t flags, uint8_t *data, size_t len, buffer_t *buf) {
  int r = 0;
  TPM2B_DIGEST dig = { .size = 0 };
  TPM2B_PUBLIC_KEY_RSA *dmsg = NULL, msg = { .size = key->public.parameters.rsaDetail.keyBits / 8 };
  TPMT_RSA_DECRYPT ds = { .scheme = TPM2_ALG_NULL };
  TPM2B_DATA label = { .size = 0 };
  TPM2_ALG_ID hashalg = TPM2_ALG_NULL;
  buffer_t *msgbuf = NULL;
  const EVP_MD *evp = NULL;
  const char *algstr = NULL;
  
  hashalg = flag_to_hash_alg(flags);

  evp = hash_alg_to_evp(hashalg);
  if (!evp) {
    r = -1;
    goto out;
  }

  r = hash(evp, &dig, data, len);
  if (r != 1) {
    r = -1;
    goto out;
  }

  msgbuf = new_buffer();
  if (!msgbuf) {
    goto out;
  }

  r = append_digestinfo(msgbuf, hashalg, &dig);
  if (r) {
    goto out;
  }

  r = add_padding(&msg, msgbuf);
  if (r) {
    goto out;
  }
  
  r = Esys_RSA_Decrypt(ctx, key->handle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
		       &msg, &ds, &label, &dmsg);
  
  algstr = rsa_hash_alg_to_string(hashalg);
  if (!algstr) {
    r = -1;
    goto out;
  }
  
  r = buf_add_string(buf, algstr);
  if (r) {
    goto out;
  }
  
  r = buf_add_data(buf, dmsg->buffer, dmsg->size);
  
 out:
  free_buffer(msgbuf);
  //EVP_MD_CTX_free(mdctx);
  return r;
}

char *curve_to_string(TPMI_ECC_CURVE curveID) {
  switch (curveID) {
  case TPM2_ECC_NIST_P192:
    return "ecdsa-sha2-nistp192";
  case TPM2_ECC_NIST_P224:
    return "ecdsa-sha2-nistp224";
  case TPM2_ECC_NIST_P256:
    return "ecdsa-sha2-nistp256";
  case TPM2_ECC_NIST_P384:
    return "ecdsa-sha2-nistp384";
  case TPM2_ECC_NIST_P521:
    return "ecdsa-sha2-nistp521";
  }
  
  return NULL;
}

TPM2_ALG_ID curve_to_hash_alg(TPMI_ECC_CURVE curveID) {
  switch (curveID) {
  case TPM2_ECC_NIST_P192:
  case TPM2_ECC_NIST_P224:
  case TPM2_ECC_NIST_P256:
    return TPM2_ALG_SHA256;
  case TPM2_ECC_NIST_P384:
    return TPM2_ALG_SHA384;
  case TPM2_ECC_NIST_P521:
    return TPM2_ALG_SHA512;
  }

  return TPM2_ALG_NULL;
}

int sign_ecdsa(ESYS_CONTEXT *ctx, tpm_key_t *key, uint8_t *data, size_t len, buffer_t *buf) {
  int r = 0;
  TPM2B_DIGEST dig = { .size = 0 };
  TPMT_SIG_SCHEME scheme = { .scheme = TPM2_ALG_ECDSA };
  TPMT_TK_HASHCHECK hck = { .tag = TPM2_ST_HASHCHECK, .hierarchy = TPM2_RH_NULL, .digest.size = 0 };
  TPMT_SIGNATURE *sig = NULL;
  buffer_t *sigbuf = NULL;
  char *curvestr = NULL;
  const EVP_MD *evp = NULL;
  
  sigbuf = new_buffer();
  if (!sigbuf) {
    r = -1;
    goto out;
  }

  scheme.details.ecdsa.hashAlg = curve_to_hash_alg(key->public.parameters.eccDetail.curveID);

  evp = hash_alg_to_evp(scheme.details.ecdsa.hashAlg);
  if (!evp) {
    r = -1;
    goto out;
  }
  
  r = hash(evp, &dig, data, len);
  if (r != 1) {
    goto out;
  }  
  
  r = Esys_Sign(ctx, key->handle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
		&dig, &scheme, &hck, &sig);
  if (r) {
    goto out;
  }

  curvestr = curve_to_string(key->public.parameters.eccDetail.curveID);
  if (!curvestr) {
    r = -1;
    goto out;
  }
  
  r = buf_add_string(buf, curvestr);
  if (r) {
    goto out;
  }
  
  r = buf_add_mpint(sigbuf, sig->signature.ecdsa.signatureR.buffer, sig->signature.ecdsa.signatureR.size);
  if (r) {
    goto out;
  }
  r = buf_add_mpint(sigbuf, sig->signature.ecdsa.signatureS.buffer, sig->signature.ecdsa.signatureS.size);
  if (r) {
    goto out;
  }

  r = buf_add_data(buf, sigbuf->data, sigbuf->len);
  
 out:
  if (sig) {
    free(sig);
  }
  if (sigbuf) {
    free_buffer(sigbuf);
  }
  return r;
}

int handle_signreq(context_t *ctx, buffer_t *msg, buffer_t *resp) {
  int r;
  uint32_t kblen, dlen, flags;
  uint8_t *keyblob, *data = NULL;
  buffer_t *sdata = NULL;
  tpm_key_t *key = NULL;
  
  
  r = buf_get_data(msg, &keyblob, &kblen);
  if (r) {
    goto out;
  }

  key = get_key_by_keyblob(ctx->keys, keyblob, kblen);
  if (!key) {
    goto out;
  }
  
  r = buf_get_data(msg, &data, &dlen);
  if (r) {
    goto out;
  }

  r = buf_get_uint32(msg, &flags);
  if (r) {
    goto out;
  }

  sdata = new_buffer();
  if (!sdata) {
    goto out;
  }

  switch (key->public.type) {
  case TPM2_ALG_RSA:
    INFO("RSA signing with %u as flags", flags);
    r = sign_rsa(ctx->esys, key, flags, data, dlen, sdata);
    if (r) {
      goto out;
    }
    break;
  case TPM2_ALG_ECC:
    r = sign_ecdsa(ctx->esys, key, data, dlen, sdata);
    if (r) {
      goto out;
    }
    break;
  default:
    goto out;
  }
  
  r = buf_add_data(resp, sdata->data, sdata->len);
  if (r) {
    goto out;
  }
  
 out:
  if (data) {
    free(data);
  }
  if (keyblob) {
    free(keyblob);
  }
  if (sdata) {
    free_buffer(sdata);
  }

  return r;
}
