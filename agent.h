/* Copyright (c) 2019 by Erik Larsson 
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#include <tss2/tss2_esys.h>
#include <syslog.h>


/* SSH agent responses */
#define SSH_AGENT_FAILURE                               5
#define SSH_AGENT_SUCCESS                               6
#define SSH_AGENT_EXTENSION_FAILURE                    28
#define SSH_AGENT_IDENTITIES_ANSWER                    12
#define SSH_AGENT_SIGN_RESPONSE                        14

/* SSH agent requests */
#define SSH_AGENTC_REQUEST_IDENTITIES                  11
#define SSH_AGENTC_SIGN_REQUEST                        13
#define SSH_AGENTC_ADD_IDENTITY                        17
#define SSH_AGENTC_REMOVE_IDENTITY                     18
#define SSH_AGENTC_REMOVE_ALL_IDENTITIES               19
#define SSH_AGENTC_ADD_ID_CONSTRAINED                  25
#define SSH_AGENTC_ADD_SMARTCARD_KEY                   20
#define SSH_AGENTC_REMOVE_SMARTCARD_KEY                21
#define SSH_AGENTC_LOCK                                22
#define SSH_AGENTC_UNLOCK                              23
#define SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED       26
#define SSH_AGENTC_EXTENSION                           27

/* sign flags */
#define SSH_AGENT_RSA_SHA2_256                         0x02
#define SSH_AGENT_RSA_SHA2_512                         0x04

/* types */
typedef struct {
  uint8_t *data;
  uint32_t len;
  uint32_t offset;
} buffer_t;

typedef struct {
  void *next;
  void *prev;
  ESYS_TR handle;
  TPMT_PUBLIC public;
} tpm_key_t;

typedef struct {
  ESYS_CONTEXT *esys;
  tpm_key_t *keys;
  const char *socketpath;
  const char *pidfile;
} context_t;


/* socket */
extern int setup_socket(context_t *, const char *);
extern int epoll_setup(int);
extern int epoll_close(int, int);
extern int epoll_loop(int, int);


/* buffer */
extern int append_buffer(buffer_t *, uint8_t *, uint32_t);
extern buffer_t *new_buffer();
extern void free_buffer();
extern int buf_get_byte(buffer_t *, uint8_t *);
extern int buf_add_byte(buffer_t *, uint8_t);
extern int buf_get_data(buffer_t *, uint8_t **, uint32_t *);
extern int buf_get_uint32(buffer_t *, uint32_t *);
extern int buf_add_uint32(buffer_t *, uint32_t);
extern int buf_add_string(buffer_t *, const char *);
extern int buf_add_data(buffer_t *, uint8_t *, uint32_t);
extern int buf_add_mpint(buffer_t *, uint8_t *, uint32_t);


/* tpm */
extern TPM2_RC tpm_generate_parent(ESYS_CONTEXT *, ESYS_TR *);
extern TPM2_RC tpm_load_file(ESYS_CONTEXT *, const char *, ESYS_TR, tpm_key_t *);
extern TPM2_RC tpm_load_handle(ESYS_CONTEXT *, TPM2_HANDLE, tpm_key_t *);
extern tpm_key_t *new_tpm_key();

/* list */
extern int handle_listreq(context_t *, buffer_t *);
extern tpm_key_t *get_key_by_keyblob(tpm_key_t *, uint8_t *, uint32_t);

/* sign */
extern int handle_signreq(context_t *, buffer_t *, buffer_t *);

/* agent messages */
extern int read_message(int, buffer_t *);
extern int write_message(int, buffer_t *);
extern int handle_message(int, context_t *, buffer_t *, buffer_t *);

/* log */
extern void setup_syslog();
extern void set_loglevel(int);
extern void agent_log(int, const char *, ...);
#define FATAL(FORMAT, ...) agent_log(LOG_CRIT, FORMAT, ##__VA_ARGS__)
#define ERROR(FORMAT, ...) agent_log(LOG_ERR, FORMAT, ##__VA_ARGS__)
#define INFO(FORMAT, ...) agent_log(LOG_INFO, FORMAT, ##__VA_ARGS__)
