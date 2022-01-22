/* Copyright (c) 2019 by Erik Larsson 
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <unistd.h>
#include <fcntl.h>
#include "agent.h"


TPM2_RC tpm_generate_parent(ESYS_CONTEXT *ctx, ESYS_TR *handle) {
  TPM2_RC tr;
  TPM2B_DATA outside = { .size = 0 };
  TPML_PCR_SELECTION pcrsel = { .count = 0 };
  TPM2B_SENSITIVE_CREATE insens = { .size = 0 };
  TPM2B_PUBLIC inpub =
    {
     .publicArea =
     {
      .type = TPM2_ALG_ECC,
      .nameAlg = TPM2_ALG_SHA256,
      .objectAttributes = TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT | TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH,
      .authPolicy = { .size = 0 },
      .parameters.eccDetail =
      {
       .symmetric =
       {
        .algorithm = TPM2_ALG_AES,
        .keyBits.aes = 128,
        .mode.aes = TPM2_ALG_CFB,
       },
       .scheme = { .scheme = TPM2_ALG_NULL },
       .curveID = TPM2_ECC_NIST_P256,
       .kdf = { .scheme = TPM2_ALG_NULL },
      },
     }
    };
  
  tr = Esys_CreatePrimary(ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &insens,
                          &inpub, &outside, &pcrsel, handle, NULL, NULL, NULL, NULL);
  if (tr) {
    return tr;
  }
  
  return 0;
}

TPM2_RC tpm_load_file(ESYS_CONTEXT *ctx, const char *path, ESYS_TR parent, tpm_key_t *key) {
  TPM2_RC tr;
  int fd ;
  ssize_t n, d = 0;
  size_t off = 0;
  uint8_t buf[1024];
  TPM2B_PUBLIC public = { .size = 0 };
  TPM2B_PRIVATE private = { .size = 0 };
  
  fd = open(path, O_RDONLY);
  if (fd == -1) {
    return -1;
  }

  do {
    n = read(fd, buf + d, 1024 -d);
    if (n == -1) {
      break;
    }
    d = d + n;
  } while (n && d < 1024);
  close(fd);
  
  if (n == -1) {
    return -1;
  }

  tr = Tss2_MU_TPM2B_PUBLIC_Unmarshal(buf, d, &off, &public);
  if (tr) {
    return tr;
  }

  tr = Tss2_MU_TPM2B_PRIVATE_Unmarshal(buf, d, &off, &private);
  if (tr) {
    return tr;
  }

  tr = Esys_Load(ctx, parent, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &private, &public, &key->handle);
  if (tr) {
    return tr;
  }

  key->public = public.publicArea;

  return 0;
}

TPM2_RC tpm_load_handle(ESYS_CONTEXT *ctx, TPM2_HANDLE handle, tpm_key_t *key) {
  TPM2_RC tr;
  TPM2B_PUBLIC *public = NULL;
  
  tr = Esys_TR_FromTPMPublic(ctx, handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &key->handle);
  if (tr) {
    return tr;
  }

  tr = Esys_ReadPublic(ctx, key->handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &public, NULL, NULL);
  if (tr) {
    return tr;
  }

  key->public = public->publicArea;
  free(public);
  
  return tr;
}

tpm_key_t *new_tpm_key() {
  tpm_key_t *key = malloc(sizeof(tpm_key_t));

  if (!key) {
    return NULL;
  }
  
  key->handle = ESYS_TR_NONE;
  key->public.type = TPM2_ALG_NULL;
  
  return key;
}
