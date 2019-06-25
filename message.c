/* Copyright (c) 2019 by Erik Larsson 
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <endian.h>
#include <string.h>
#include <errno.h>
#include "agent.h"


#define MAX_DATA_LEN 1048576


int read_message(int fd, buffer_t *msg) {
  int r;
  ssize_t n, d = 0;
  uint32_t msgbuf = 0, msglen = 0;
  uint8_t rbuf[1024];

  n = read(fd, &msgbuf, 4);
  if (n == -1) {
    return -1;
  }
  if (n < 4) {
    return -1;
  }

  msglen = be32toh(msgbuf);

  if (!msglen) {
    return -1;
  }

  if (msglen > MAX_DATA_LEN) {
    return -1;
  }
  
  do {
    memset(rbuf, 0, 1024);
    n = read(fd, rbuf, 1024);
    if (n == -1) {
      r = n;
      goto err_free;
    }
    r = append_buffer(msg, rbuf, n);
    if (r) {
      goto err_free;
    }
    d = d + n;
  } while (n && d < msglen);

  if (d < msglen) {
    goto err_free;
  }
  
  return 0;

 err_free:
  free_buffer(msg);

  return r;
}

int write_message(int fd, buffer_t *msg) {
  ssize_t n, d = 0;
  uint32_t len;

  len = htobe32(msg->len);
  n = write(fd, &len, 4);
  if (n == -1) {
    return -1;
  }
  if (n != 4) {
    return -1;
  }
  
  while (n && d < msg->len) {
    n = write(fd, msg->data + d, msg->len - d);
    if (n == -1) {
      return -1;
    }
    d = d + n;
  }

  if (d < msg->len) {
    return -1;
  }
  
  return 0;
}

int handle_message(int fd, context_t *ctx, buffer_t *msg, buffer_t *rmsg) {
  int r;
  uint8_t type;
  
  r = read_message(fd, msg);
  if (r) {
    return r;
  }

  r = buf_get_byte(msg, &type);
  if (r) {
    return r;
  }

  switch (type) {
  case SSH_AGENTC_REQUEST_IDENTITIES:
    r = buf_add_byte(rmsg, SSH_AGENT_IDENTITIES_ANSWER);
    if (r) {
      return r;
    }

    r = handle_listreq(ctx, rmsg);
    if (r) {
      return r;
    }
    break;
  case SSH_AGENTC_SIGN_REQUEST:
    r = buf_add_byte(rmsg, SSH_AGENT_SIGN_RESPONSE);
    if (r) {
      return r;
    }
    r = handle_signreq(ctx, msg, rmsg);
    if (r) {
      return r;
    }
    break;
  default:
    return -1;
  }
  
  return 0;
}
