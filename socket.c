/* Copyright (c) 2019 by Erik Larsson 
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "agent.h"


int setup_socket(context_t *ctx, const char *path) {
  int r, sfd;
  struct sockaddr_un sname = { .sun_family = AF_UNIX };

  if (strlen(path) > (sizeof(sname.sun_path) - 1)) {
    errno = EOVERFLOW;
    return -1;
  }

  strncpy(sname.sun_path, path, sizeof(sname.sun_path) - 1); 
  
  sfd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sfd == -1) {
    return -1;
  }
  
  r = fchmod(sfd, S_IRUSR | S_IWUSR);
  if (r) {
    return r;
  }
  
  r = bind(sfd, (const struct sockaddr *) &sname, sizeof(struct sockaddr_un));
  if (r) {
    return r;
  }

  ctx->socketpath = path;
  
  r = listen(sfd, 10);
  if (r) {
    return r;
  }
  
  return sfd;
}

int epoll_setup(int sfd) {
  int r, pfd;
  struct epoll_event ev = { .events = EPOLLIN };

  pfd = epoll_create1(0);
  if (pfd == -1) {
    return -1;
  }

  ev.data.fd = sfd;
  r = epoll_ctl(pfd, EPOLL_CTL_ADD, sfd, &ev);
  if (r == -1) {
    return -1;
  }

  return pfd;
}

int epoll_close(int pfd, int fd) {
  int r;

  r = epoll_ctl(pfd, EPOLL_CTL_DEL, fd, NULL);
  close(fd);

  return r;
}

int epoll_loop(int pfd, int sfd) {
  int r, fd;
  struct epoll_event rev, ev = { .events = EPOLLIN };
  
  r = epoll_wait(pfd, &rev, 1, -1);
  if (r == -1) {
    return -1;
  }

  if (rev.data.fd == sfd) {
    fd = accept(sfd, NULL, NULL);
    if (fd == -1) {
      return -1;
    }
    ev.data.fd = fd;
    r = epoll_ctl(pfd, EPOLL_CTL_ADD, fd, &ev);
    if (r == -1) {
      return -1;
    }
    return 0;
  }
  else if (rev.events & EPOLLHUP) {
    r = epoll_close(pfd, rev.data.fd);
    return r;
  }
  else if (rev.events & EPOLLIN) {
    return rev.data.fd;
  }
  
  return 0;
}
