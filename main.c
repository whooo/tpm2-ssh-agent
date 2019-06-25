/* Copyright (c) 2019 by Erik Larsson 
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#include <tss2/tss2_esys.h>
#include <sys/socket.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <search.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include "agent.h"


static context_t *global_ctx = NULL;

struct keypath {
  struct keypath *next;
  struct keypath *prev;
  char *path;
  TPM2_HANDLE handle;
};

struct keypath *new_keypath() {
  struct keypath *kp = NULL;
  kp = malloc(sizeof(struct keypath));
  if (!kp) {
    return NULL;
  }

  kp->path = NULL;
  kp->handle = 0;
  
  return kp;
}

struct keypath *add_filekey(struct keypath *que, const char *path) {
  struct keypath *kp = new_keypath();
  kp->path = strdup(path);
  insque(kp, que);
  if (que) {
    return que;
  }
  return kp;
}

struct keypath *add_handlekey(struct keypath *que, TPM2_HANDLE handle) {
  struct keypath *kp = new_keypath();
  kp->handle = handle;
  insque(kp, que);
  if (que) {
    return que;
  }
  return kp;

}

struct keypath *pop_keypath(struct keypath *que) {
  struct keypath *next = que->next, *kp = que;

  if (!kp) {
    return NULL;
  }

  remque(kp);
  
  if (kp->path) {
    free(kp->path);
  }
  free(kp);
  
  return next;
}

int need_parent(struct keypath *que) {
  struct keypath *key = que;

  while (key) {
    if (key->path) {
      return 1;
    }
    key = key->next;
  }
  
  return 0;
}

TPM2_HANDLE str_to_handle(const char *str) {
  TPM2_HANDLE handle;
  unsigned long tl = 0;

  tl = strtoul(str, NULL, 0);
  handle = tl & 0xFFFFFFFF;
  if (!(handle & TPM2_HR_PERSISTENT) && !(handle & TPM2_HR_TRANSIENT)) {
    return -1;
  }
  
  return handle;
}

context_t *new_context() {
  context_t *ctx = NULL;

  ctx = malloc(sizeof(context_t));
  if (!ctx) {
    return NULL;
  }

  ctx->esys = NULL;
  ctx->keys = NULL;
  ctx->socketpath = NULL;
  ctx->pidfile = NULL;

  return ctx;
}

void cleanup() {
  if (!global_ctx) {
    return;
  }
  
  if (global_ctx->socketpath) {
    unlink(global_ctx->socketpath);
  }

  if (global_ctx->pidfile) {
    unlink(global_ctx->pidfile);
  }

  if (global_ctx->esys) {
    Esys_Finalize(&global_ctx->esys);
  }
}

void sigexit(int signal) {
  exit(0);
};

void usage(const char *name) {
  printf("Usage: %s [OPTIONS]\n"
	 "Options:\n"
	 "  -s, --socket=PATH\t\tPath for agent socket\n"
	 "  -k, --key=PATH\t\tPath to keyfile\n"
	 "  -i, --key-handle=HANDLE\tHandle for persistant object\n"
	 "  -p, --pidfile=PATH\t\tPath for pidfile\n"
	 "  -f, --foreground\t\tRun in foreground\n"
	 "  -h, --help\t\t\tShow this help\n",
	 name);
}

int setup_pidfile(context_t *ctx, const char *path) {
  int r, fd;
  pid_t mpid = 0;
  
  fd = open(path, O_WRONLY | O_EXCL | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  if (fd == -1) {
    return -1;
  }

  ctx->pidfile = path;
  
  mpid = getpid();
  
  r = dprintf(fd, "%u\n", mpid);
  if (r < 0) {
    return -1;
  }

  r = close(fd);

  return r;
}

int main(int argc, char **argv) {
  int r, c, optind, sfd, fd, pfd, fg = 0, loglevel = LOG_WARNING;
  char *spath = NULL, *pidfile = NULL;
  buffer_t *msg = NULL, *rmsg = NULL, *failmsg = NULL;
  TPM2_HANDLE handle;
  ESYS_TR parent;
  struct keypath *kpaths = NULL;
  tpm_key_t *key = NULL;
  context_t *ctx = NULL;
  struct sigaction sigact =
    {
     .sa_handler = sigexit,
     .sa_flags = 0,
    };

  sigemptyset(&sigact.sa_mask);

  ctx = new_context();
  if (!ctx) {
    FATAL("new_context: %s\n", strerror(errno));
  }

  global_ctx = ctx;
  
  r = atexit(cleanup);
  if (r) {
    FATAL("atexit: %s\n", strerror(errno));
  }

  r = sigaction(SIGINT, &sigact, NULL);
  if (r) {
    FATAL("sigaction: %s\n", strerror(errno));
  }

  r = sigaction(SIGTERM, &sigact, NULL);
  if (r) {
    FATAL("sigaction: %s\n", strerror(errno));
  }

  struct option opts[] =
    {
     {"socket",      required_argument, 0, 's'},
     {"key",         required_argument, 0, 'k'},
     {"key-handle",  required_argument, 0, 'i'},
     {"pidfile",     required_argument, 0, 'p'},
     {"foreground",  no_argument,       0, 'f'},
     {"verbose",     no_argument,       0, 'v'},
     {"help",        no_argument,       0, 'h'},
     {0, 0, 0, 0},
    };

  while (1) {
    c = getopt_long(argc, argv, "s:k:i:p:fvh", opts, &optind);
    if (c == -1) {
      break;
    }

    switch (c) {
    case 's':
      spath = strdup(optarg);
      break;
    case 'k':
      kpaths = add_filekey(kpaths, optarg);
      break;
    case 'i':
      handle = str_to_handle(optarg);
      if (handle == -1) {
	dprintf(2, "bad key handle: %s\n", optarg);
	return 1;
      }
      kpaths = add_handlekey(kpaths, handle);
      break;
    case 'p':
      pidfile = strdup(optarg);
      break;
    case 'f':
      fg = 1;
      break;
    case 'v':
      if (loglevel < LOG_DEBUG) {
	loglevel++;
	set_loglevel(loglevel);
      }
      break;
    case 'h':
      usage(argv[0]);
      return 1;
    default:
      usage(argv[0]);
      return 1;
    }
  }

  if (!spath) {
    FATAL("missing socket path");
    return 1;
  }

  if (!kpaths) {
    FATAL("no keys specified");
    return 1;
  }
  
  r = Esys_Initialize(&ctx->esys, NULL, NULL);
  if (r) {
    FATAL("Esys_Initialize: %#x", r);
  }

  if (need_parent(kpaths)) {
    r = tpm_generate_parent(ctx->esys, &parent);
    if (r) {
      FATAL("tpm_generate_parent: %#x", r);
    }
  }


  while (kpaths) {
    key = new_tpm_key();
    if (!key) {
      FATAL("new_tpm_key: %s", strerror(errno));
    }
    if (kpaths->path) {
      r = tpm_load_file(ctx->esys, kpaths->path, parent, key);
      if (r == -1) {
	FATAL("tpm_load_file (%s): %s", kpaths->path, strerror(errno));
      }
      else if (r) {
	FATAL("tpm_load_file (%s): %#x", kpaths->path, r);
      }
    }
    else if (kpaths->handle) {
      r = tpm_load_handle(ctx->esys, kpaths->handle, key);
      if (r) {
	FATAL("tpm_load_handle (%#x): %s", kpaths->handle, strerror(errno));
      }
    }
    insque(key, ctx->keys);
    if (!ctx->keys) {
      ctx->keys = key;
    }
    kpaths = pop_keypath(kpaths);
  }
  
  
  sfd = setup_socket(ctx, spath);
  if (sfd == -1) {
    FATAL("Unable to setup socket: %s", strerror(errno));
    return 1;
  }

  ctx->socketpath = spath;

  pfd = epoll_setup(sfd);
  if (pfd == -1) {
    FATAL("epoll_setup: %s", strerror(errno));
    return 1;
  }

  failmsg = new_buffer();
  r = buf_add_byte(failmsg, SSH_AGENT_FAILURE);
  if (r) {
    FATAL("buf_add_byte: %s", strerror(errno));
    return 1;
  }

  if (!fg) {
    r = daemon(0, 0);
    if (r) {
      FATAL("daemon: %s\n", strerror(errno));
    }
    setup_syslog();
  }

  if (pidfile) {
    r = setup_pidfile(ctx, pidfile);
    if (r) {
      FATAL("setup_pidfile: %s\n", strerror(errno));
    }
  }

  while (1) {
    fd = epoll_loop(pfd, sfd);
    switch (fd) {
    case 0:
      continue;
    case -1:
      ERROR("epoll_loop: %s", strerror(errno));
      continue;
    }
    
    msg = new_buffer();
    rmsg = new_buffer();
    if (!msg || !rmsg) {
      ERROR("new_buffer: %s", strerror(errno));
      continue;
    }

    r = handle_message(fd, ctx, msg, rmsg);
    if (r) {
      write_message(fd, failmsg);
      epoll_close(pfd, fd);
    } else {
      write_message(fd, rmsg);
    }

    free_buffer(msg);
    free_buffer(rmsg);      
  }  
  
  return 0;
}
