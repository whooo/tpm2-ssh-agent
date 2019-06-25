/* Copyright (c) 2019 by Erik Larsson 
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <endian.h>
#include "agent.h"


buffer_t *new_buffer() {
  buffer_t *b = NULL;

  b = malloc(sizeof(buffer_t));
  if (!b) {
    return NULL;
  }

  b->data = NULL;
  b->len = 0;
  b->offset = 0;
  
  return b;
};

void free_buffer(buffer_t *buf) {
  if (!buf) {
    return;
  }
  
  if (buf->data) {
    free(buf->data);
  }

  free(buf);
}

int append_buffer(buffer_t *buf, uint8_t *data, uint32_t len) {
  uint8_t *n = NULL;
  
  if ((buf->len + len) > UINT32_MAX) {
    errno = ERANGE;
    return -1;
  }

  n = realloc(buf->data, buf->len + len);
  if (!n) {
    return -1;
  }
  
  buf->data = n;

  memcpy(buf->data + buf->len, data, len);

  buf->len = buf->len + len;
  
  return 0;
}

int check_offset(buffer_t *buf, uint32_t len) {
  if ((buf->offset + len) > buf->len) {
    return 0;
  }

  return 1;
}

int buf_add_byte(buffer_t *buf, uint8_t byte) {
  int r;

  r = append_buffer(buf, &byte, 1);
  
  return r;
}

int buf_get_byte(buffer_t *buf, uint8_t *byte) {
  if (!check_offset(buf, 1)) {
    errno = ERANGE;
    return -1;
  }

  *byte = buf->data[buf->offset];
  buf->offset++;
  
  return 0;
}

int buf_add_uint32(buffer_t *buf, uint32_t data) {
  int r;
  
  uint32_t be = htobe32(data);

  r = append_buffer(buf, (void *) &be, 4);

  return r;
}

int buf_get_uint32(buffer_t *buf, uint32_t *data) {
  uint32_t be;
  
  if (!check_offset(buf, 4)) {
    errno = ERANGE;
    return -1;
  }

  memcpy(&be, buf->data + buf->offset, 4);
  *data = be32toh(be);

  buf->offset = buf->offset + 4;
  
  return 0;
}

int buf_add_string(buffer_t *buf, const char *data) {
  int r;
  size_t slen;

  slen = strlen(data);
  if (slen > UINT32_MAX) {
    errno = ERANGE;
    return -1;
  }
  
  r = buf_add_uint32(buf, slen);
  if (r) {
    return r;
  }

  r = append_buffer(buf, (uint8_t *) data, slen);
  
  return r;
}

int buf_add_data(buffer_t *buf, uint8_t *data, uint32_t len) {
  int r;

  r = buf_add_uint32(buf, len);
  if (r) {
    return r;
  }

  r = append_buffer(buf, data, len);

  return r;
}

int buf_get_data(buffer_t *buf, uint8_t **data, uint32_t *len) {
  int r;
  uint32_t l;

  r = buf_get_uint32(buf, &l);
  if (r) {
    return r;
  }

  if (!check_offset(buf, l)) {
    errno = ERANGE;
    return -1;
  }

  *data = malloc(l);
  if (!*data) {
    return -1;
  }

  memcpy(*data, buf->data + buf->offset, l);
  
  buf->offset = buf->offset + l;

  *len = l;
  
  return 0;
}

int buf_add_mpint(buffer_t *buf, uint8_t *data, uint32_t len) {
  int r, i = 0;
  uint32_t nbytes = 0;
  uint8_t *first;

  if (!len) {
    r = buf_add_uint32(buf, nbytes);
    return r;
  }

  nbytes = len;
  for (i=0;i < len && data[i] == 0;i++) {
    nbytes--;
  }

  first = data + i;
  if (first[0] & 0x80) {
    r = buf_add_uint32(buf, nbytes + 1);
    if (r) {
      return r;
    }
    r = buf_add_byte(buf, 0);
    if (r) {
      return r;
    }
  } else {
    r = buf_add_uint32(buf, nbytes);
    if (r) {
      return r;
    }
  }
  r = append_buffer(buf, first, nbytes);
  
  return r;
}
