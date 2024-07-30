#define _GNU_SOURCE
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <libyang/libyang.h>
#include <nc_client.h>

#ifdef NC_ENABLED_TLS
#   include <openssl/pem.h>
#   include <openssl/x509v3.h>
#endif

#ifndef HAVE_EACCESS
#define eaccess access
#endif

#include "commands.h"
#include "compat.h"
#include "completion.h"
#include "configuration.h"

#include "oru_controller_api.h"

#define CLI_CH_TIMEOUT 60 /* 1 minute */
#define CLI_RPC_REPLY_TIMEOUT 5 /* 5 seconds */

extern oru_controller_t oru_cont;

int netconf_call_home();
int netconf_status();
int netconf_get();
int netconf_subscribe();
