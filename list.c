/* Copyright (c) 2019 by Erik Larsson 
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#include <tss2/tss2_tpm2_types.h>
#include <endian.h>
#include <string.h>
#include "agent.h"



int append_rsa_key(buffer_t *buf, TPMT_PUBLIC *public) {
  int r;
  buffer_t *tmp;
  uint32_t e;
  
  tmp = new_buffer();
  if (!tmp) {
    return -1;
  }
  
  r = buf_add_string(tmp, "ssh-rsa");
  if (r) {
    goto err_free;
  }

  e = public->parameters.rsaDetail.exponent;
  if (!e) {
    e = 65537;
  }
  e = htobe32(e);

  r = buf_add_mpint(tmp, (void *) &e, 4);
  if (r) {
    goto err_free;
  }

  r = buf_add_mpint(tmp, public->unique.rsa.buffer, public->unique.rsa.size);
  if (r) {
    goto err_free;
  }
  
  r = buf_add_data(buf, tmp->data, tmp->len);
  
 err_free:
  free_buffer(tmp);
  return r;
}

int append_ecc_key(buffer_t *buf, TPMT_PUBLIC *public) {
  int r = 0;
  buffer_t *tmp;
  uint32_t xylen;
  
  tmp = new_buffer();
  if (!tmp) {
    return -1;
  }

  switch (public->parameters.eccDetail.curveID) {
  case TPM2_ECC_NIST_P256:
    r = buf_add_string(tmp, "ecdsa-sha2-nistp256");
    if (r) {
      goto err_free;
    }
    r = buf_add_string(tmp, "nistp256");
    if (r) {
      goto err_free;
    }
    break;
  default:
    r = -1;
    goto err_free;
  }

  xylen = public->unique.ecc.x.size + public->unique.ecc.y.size;

  r = buf_add_uint32(tmp, xylen + 1);
  if (r) {
    goto err_free;
  }

  r = buf_add_byte(tmp, 4);
  if (r) {
    goto err_free;
  }

  r = append_buffer(tmp, public->unique.ecc.x.buffer, public->unique.ecc.x.size);
  if (r) {
    goto err_free;
  }

  r = append_buffer(tmp, public->unique.ecc.y.buffer, public->unique.ecc.y.size);
  if (r) {
    goto err_free;
  }

  r = buf_add_data(buf, tmp->data, tmp->len);
  
 err_free:
  free_buffer(tmp);
  return r;
  
}

int handle_listreq(context_t *ctx, buffer_t *msg) {
  int r;
  uint32_t nkeys = 0;
  tpm_key_t *key = ctx->keys;
  buffer_t *kbuf = NULL;
  
  while (key) {
    nkeys++;
    key = key->next;
  }

  r = buf_add_uint32(msg, nkeys);
  if (r) {
    return r;
  }

  key = ctx->keys;
  while (key) {
    kbuf = new_buffer();
    if (!kbuf) {
      return -1;
    }
    switch (key->public.type) {
    case TPM2_ALG_RSA:
      r = append_rsa_key(kbuf, &key->public);
      if (r) {
	return r;
      }
      break;
    case TPM2_ALG_ECC:
      r = append_ecc_key(kbuf, &key->public);
      if (r) {
	return r;
      }
      break;
    default:
      return -1;
    }
    r = append_buffer(msg, kbuf->data, kbuf->len);
    if (r) {
      return r;
    }
    r = buf_add_string(msg, "");
    if (r) {
      return r;
    }
    key = key->next;
    free_buffer(kbuf);
  }
  
  return 0;
}

tpm_key_t *get_key_by_keyblob(tpm_key_t *keys, uint8_t *blob, uint32_t len) {
  int r;
  buffer_t *buf = NULL;
  tpm_key_t *key = NULL;
  
  while (keys) {
    buf = new_buffer();

    switch (keys->public.type) {
    case TPM2_ALG_RSA:
      r = append_rsa_key(buf, &keys->public);
      if (r) {
	goto out;
      }
      break;
    case TPM2_ALG_ECC:
      r = append_ecc_key(buf, &keys->public);
      if (r) {
	goto out;
      }
      break;
    default:
      break;
    }

    if ((buf->len - 4) == len && !memcmp(blob, buf->data + 4, len)) {
      key = keys;
      goto out;
    }
    
    free_buffer(buf);
    buf = NULL;
    keys = keys->next;
  }

 out:
  free_buffer(buf);
  return key;
}
