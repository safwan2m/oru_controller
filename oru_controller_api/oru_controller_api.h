#ifndef __ORU_CONTROLLER_API__
#define __ORU_CONTROLLER_API__

#include "sysrepo.h"

typedef struct oru_controller_s{
    sr_conn_ctx_t *connection;
    sr_session_ctx_t *session;
    sr_datastore_t ds; 
    char *user;
    char *host;
    unsigned short port;
    int timeout; 
}oru_controller_t;

#endif
