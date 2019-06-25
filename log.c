/* Copyright (c) 2019 by Erik Larsson 
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#include <syslog.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

static int do_syslog = 0;
static int loglevel = 0;

void setup_syslog() {
  openlog(NULL, LOG_NOWAIT, LOG_DAEMON);
  setlogmask(loglevel);
  do_syslog = 1;
}

void set_loglevel(int prio) {
  loglevel = prio;
}

void agent_log(int prio, const char *format, ...) {
  va_list ap;

  va_start(ap, format);

  if (prio > loglevel) {
    return;
  }
  
  switch (do_syslog) {
  case 0:
    vdprintf(2, format, ap);
    dprintf(2, "\n");
    break;
  case 1:
    vsyslog(prio, format, ap);
    break;
  }

  va_end(ap);

  if (prio == LOG_CRIT) {
    exit(1);
  }
}


