#include"netconf_cli_api.h"

extern volatile int exit_application;

char some_msg[4096];

extern int done;
LYD_FORMAT output_format = LYD_XML;
uint32_t output_flag;
char *config_editor;
struct nc_session *session;
volatile int interleave;
int timed;

enum sync_state{
    FREERUN,
    HOLDOVER,
    LOCKED,

}sync_state_var;

#define NC_CAP_WRITABLERUNNING_ID "urn:ietf:params:netconf:capability:writable-running"
#define NC_CAP_CANDIDATE_ID       "urn:ietf:params:netconf:capability:candidate"
#define NC_CAP_CONFIRMEDCOMMIT_ID "urn:ietf:params:netconf:capability:confirmed-commit:1.1"
#define NC_CAP_ROLLBACK_ID        "urn:ietf:params:netconf:capability:rollback-on-error"
#define NC_CAP_VALIDATE10_ID      "urn:ietf:params:netconf:capability:validate:1.0"
#define NC_CAP_VALIDATE11_ID      "urn:ietf:params:netconf:capability:validate:1.1"
#define NC_CAP_STARTUP_ID         "urn:ietf:params:netconf:capability:startup"
#define NC_CAP_URL_ID             "urn:ietf:params:netconf:capability:url"
#define NC_CAP_XPATH_ID           "urn:ietf:params:netconf:capability:xpath"
#define NC_CAP_WITHDEFAULTS_ID    "urn:ietf:params:netconf:capability:with-defaults"
#define NC_CAP_NOTIFICATION_ID    "urn:ietf:params:netconf:capability:notification"
#define NC_CAP_INTERLEAVE_ID      "urn:ietf:params:netconf:capability:interleave"

#define client_opts nc_client_context_location()->opts
#define ssh_opts nc_client_context_location()->ssh_opts
#define ssh_ch_opts nc_client_context_location()->ssh_ch_opts
static int cmd_disconnect(const char *arg, char **tmp_config_file);

struct arglist {
    char **list;
    int count;
    int size;
};

static void
init_arglist(struct arglist *args)
{
    if (args != NULL) {
        args->list = NULL;
        args->count = 0;
        args->size = 0;
    }
}

static void
clear_arglist(struct arglist *args)
{
    int i = 0;

    if (args && args->list) {
        for (i = 0; i < args->count; i++) {
            if (args->list[i]) {
                free(args->list[i]);
            }
        }
        free(args->list);
    }

    init_arglist(args);
}

static int
cli_gettimespec(struct timespec *ts, int *mono)
{
    errno = 0;

#ifdef CLOCK_MONOTONIC_RAW
    *mono = 1;
    return clock_gettime(CLOCK_MONOTONIC_RAW, ts);
#elif defined (CLOCK_MONOTONIC)
    *mono = 1;
    return clock_gettime(CLOCK_MONOTONIC, ts);
#elif defined (CLOCK_REALTIME)
    /* no monotonic clock available, return realtime */
    *mono = 0;
    return clock_gettime(CLOCK_REALTIME, ts);
#else
    *mono = 0;

    int rc;
    struct timeval tv;

    rc = gettimeofday(&tv, NULL);
    if (!rc) {
        ts->tv_sec = (time_t)tv.tv_sec;
        ts->tv_nsec = 1000L * (long)tv.tv_usec;
    }
    return rc;
#endif
}

/* returns milliseconds */
static int32_t
cli_difftimespec(const struct timespec *ts1, const struct timespec *ts2)
{
    int64_t nsec_diff = 0;

    nsec_diff += (((int64_t)ts2->tv_sec) - ((int64_t)ts1->tv_sec)) * 1000000000L;
    nsec_diff += ((int64_t)ts2->tv_nsec) - ((int64_t)ts1->tv_nsec);

    return nsec_diff ? nsec_diff / 1000000L : 0;
}

int
cli_send_recv(struct nc_rpc *rpc, FILE *output, NC_WD_MODE wd_mode, int timeout_s)
{
    char *model_data;
    int ret = 0, mono;
    int32_t msec;
    uint32_t ly_wd;
    uint64_t msgid;
    struct lyd_node *envp, *op, *err, *node, *info;
    struct lyd_node_any *any;
    NC_MSG_TYPE msgtype;
    struct timespec ts_start, ts_stop;

    if (timed) {
        ret = cli_gettimespec(&ts_start, &mono);
        if (ret) {
            ERROR(__func__, "Getting current time failed (%s).", strerror(errno));
            return ret;
        }
    }

    msgtype = nc_send_rpc(session, rpc, 1000, &msgid);
    if (msgtype == NC_MSG_ERROR) {
        ERROR(__func__, "Failed to send the RPC.");
        if (nc_session_get_status(session) != NC_STATUS_RUNNING) {
            cmd_disconnect(NULL, NULL);
        }
        return -1;
    } else if (msgtype == NC_MSG_WOULDBLOCK) {
        ERROR(__func__, "Timeout for sending the RPC expired.");
        return -1;
    }

recv_reply:
    msgtype = nc_recv_reply(session, rpc, msgid, timeout_s * 1000, &envp, &op);
    if (msgtype == NC_MSG_ERROR) {
        ERROR(__func__, "Failed to receive a reply.");
        if (nc_session_get_status(session) != NC_STATUS_RUNNING) {
            cmd_disconnect(NULL, NULL);
        }
        return -1;
    } else if (msgtype == NC_MSG_WOULDBLOCK) {
        ERROR(__func__, "Timeout for receiving a reply expired.");
        return -1;
    } else if (msgtype == NC_MSG_NOTIF) {
        /* read again */
        goto recv_reply;
    } else if (msgtype == NC_MSG_REPLY_ERR_MSGID) {
        /* unexpected message, try reading again to get the correct reply */
        ERROR(__func__, "Unexpected reply received - ignoring and waiting for the correct reply.");
        lyd_free_tree(envp);
        lyd_free_tree(op);
        goto recv_reply;
    }

    if (timed) {
        ret = cli_gettimespec(&ts_stop, &mono);
        if (ret) {
            ERROR(__func__, "Getting current time failed (%s).", strerror(errno));
            goto cleanup;
        }
    }

    if (op) {
        /* data reply */
        if (nc_rpc_get_type(rpc) == NC_RPC_GETSCHEMA) {
            /* special case */
            if (!lyd_child(op) || (lyd_child(op)->schema->nodetype != LYS_ANYXML)) {
                ERROR(__func__, "Unexpected data reply to <get-schema> RPC.");
                ret = -1;
                goto cleanup;
            }
            if (output == stdout) {
                fprintf(output, "MODULE\n");
            }
            any = (struct lyd_node_any *)lyd_child(op);
            switch (any->value_type) {
            case LYD_ANYDATA_STRING:
            case LYD_ANYDATA_XML:
                fputs(any->value.str, output);
                break;
            case LYD_ANYDATA_DATATREE:
                lyd_print_mem(&model_data, any->value.tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
                fputs(model_data, output);
                free(model_data);
                break;
            default:
                /* none of the others can appear here */
                ERROR(__func__, "Unexpected anydata value format.");
                ret = -1;
                goto cleanup;
            }

            if (output == stdout) {
                fprintf(output, "\n");
            }
        } else {
            /* generic data */
            if (output == stdout) {
                fprintf(output, "DATA\n");
            }

            switch (wd_mode) {
            case NC_WD_ALL:
                ly_wd = LYD_PRINT_WD_ALL;
                break;
            case NC_WD_ALL_TAG:
                ly_wd = LYD_PRINT_WD_ALL_TAG;
                break;
            case NC_WD_TRIM:
                ly_wd = LYD_PRINT_WD_TRIM;
                break;
            case NC_WD_EXPLICIT:
                ly_wd = LYD_PRINT_WD_EXPLICIT;
                break;
            default:
                ly_wd = 0;
                break;
            }

            lyd_print_file(output, lyd_child(op), output_format, LYD_PRINT_WITHSIBLINGS | ly_wd | output_flag);
            if (output == stdout) {
                fprintf(output, "\n");
            }


            printf("op->schema->name is %s\n",op->schema->name);
            struct lyd_node *node = lyd_child(op);
            printf("node->schema->name is %s\n", node->schema->name);
            lyd_print_file(output, op, output_format, LYD_PRINT_WITHSIBLINGS | ly_wd | output_flag);

            LY_LIST_FOR(lyd_child(op), node) {
                printf("iterated ... %s\n", node->schema->name);
                if (strcmp(node->schema->name, "sync-state") == 0) {
                    printf("sync-state is unknown\n");
                }
            }
            
            const char *xml_content = lyd_get_value(node);
            printf("value is \n %s\n",xml_content);
        }
    } else if (!strcmp(LYD_NAME(lyd_child(envp)), "ok")) {
        /* ok reply */
        fprintf(output, "OK\n");
    } else {
        assert(!strcmp(LYD_NAME(lyd_child(envp)), "rpc-error"));

        fprintf(output, "ERROR\n");
        LY_LIST_FOR(lyd_child(envp), err) {
            lyd_find_sibling_opaq_next(lyd_child(err), "error-type", &node);
            if (node) {
                fprintf(output, "\ttype:     %s\n", ((struct lyd_node_opaq *)node)->value);
            }
            lyd_find_sibling_opaq_next(lyd_child(err), "error-tag", &node);
            if (node) {
                fprintf(output, "\ttag:      %s\n", ((struct lyd_node_opaq *)node)->value);
            }
            lyd_find_sibling_opaq_next(lyd_child(err), "error-severity", &node);
            if (node) {
                fprintf(output, "\tseverity: %s\n", ((struct lyd_node_opaq *)node)->value);
            }
            lyd_find_sibling_opaq_next(lyd_child(err), "error-app-tag", &node);
            if (node) {
                fprintf(output, "\tapp-tag:  %s\n", ((struct lyd_node_opaq *)node)->value);
            }
            lyd_find_sibling_opaq_next(lyd_child(err), "error-path", &node);
            if (node) {
                fprintf(output, "\tpath:     %s\n", ((struct lyd_node_opaq *)node)->value);
            }
            lyd_find_sibling_opaq_next(lyd_child(err), "error-message", &node);
            if (node) {
                fprintf(output, "\tmessage:  %s\n", ((struct lyd_node_opaq *)node)->value);
            }

            info = lyd_child(err);
            while (!lyd_find_sibling_opaq_next(info, "error-info", &info)) {
                fprintf(output, "\tinfo:\n");
                lyd_print_file(stdout, lyd_child(info), LYD_XML, LYD_PRINT_WITHSIBLINGS);

                info = info->next;
            }
            fprintf(output, "\n");
        }
        ret = 1;
    }

    if (msgtype == NC_MSG_REPLY_ERR_MSGID) {
        ERROR(__func__, "Trying to receive another message...\n");
        lyd_free_tree(envp);
        lyd_free_tree(op);
        goto recv_reply;
    }

    if (timed) {
        msec = cli_difftimespec(&ts_start, &ts_stop);
        fprintf(output, "%s %2dm%d.%03ds\n", mono ? "mono" : "real", msec / 60000, (msec % 60000) / 1000, msec % 1000);
    }

cleanup:
    lyd_free_tree(envp);
    lyd_free_tree(op);
    return ret;
}

static int
addargs(struct arglist *args, char *format, ...)
{
    va_list arguments;
    char *aux = NULL, *aux1 = NULL, *prev_aux, quot;
    int spaces;

    if (args == NULL) {
        return EXIT_FAILURE;
    }

    /* store arguments to aux string */
    va_start(arguments, format);
    if (vasprintf(&aux, format, arguments) == -1) {
        va_end(arguments);
        ERROR(__func__, "vasprintf() failed (%s)", strerror(errno));
        return EXIT_FAILURE;
    }
    va_end(arguments);

    /* remember the begining of the aux string to free it after operations */
    aux1 = aux;

    /*
     * get word by word from given string and store words separately into
     * the arglist
     */
    prev_aux = NULL;
    quot = 0;
    for (aux = strtok(aux, " \n\t"); aux; prev_aux = aux, aux = strtok(NULL, " \n\t")) {
        if (!strcmp(aux, "")) {
            continue;
        }

        if (!args->list) { /* initial memory allocation */
            if ((args->list = (char **)malloc(8 * sizeof(char *))) == NULL) {
                ERROR(__func__, "Memory allocation failed (%s:%d)", __FILE__, __LINE__);
                return EXIT_FAILURE;
            }
            args->size = 8;
            args->count = 0;
        } else if (!quot && (args->count + 2 >= args->size)) {
            /*
             * list is too short to add next to word so we have to
             * extend it
             */
            args->size += 8;
            args->list = realloc(args->list, args->size * sizeof(char *));
        }

        if (!quot) {
            /* add word at the end of the list */
            if ((args->list[args->count] = malloc((strlen(aux) + 1) * sizeof(char))) == NULL) {
                ERROR(__func__, "Memory allocation failed (%s:%d)", __FILE__, __LINE__);
                return EXIT_FAILURE;
            }

            /* quoted argument */
            if ((aux[0] == '\'') || (aux[0] == '\"')) {
                quot = aux[0];
                ++aux;
                /* ...but without spaces */
                if (aux[strlen(aux) - 1] == quot) {
                    quot = 0;
                    aux[strlen(aux) - 1] = '\0';
                }
            }

            strcpy(args->list[args->count], aux);
            args->list[++args->count] = NULL; /* last argument */
        } else {
            /* append another part of the argument */
            spaces = aux - (prev_aux + strlen(prev_aux));
            args->list[args->count - 1] = realloc(args->list[args->count - 1],
                    strlen(args->list[args->count - 1]) + spaces + strlen(aux) + 1);

            /* end of quoted argument */
            if (aux[strlen(aux) - 1] == quot) {
                quot = 0;
                aux[strlen(aux) - 1] = '\0';
            }

            sprintf(args->list[args->count - 1] + strlen(args->list[args->count - 1]), "%*s%s", spaces, " ", aux);
        }
    }

    /* clean up */
    free(aux1);

    return EXIT_SUCCESS;
}

static char *
trim_top_elem(char *data, const char *top_elem, const char *top_elem_ns)
{
    char *ptr, *prefix = NULL, *buf;
    int pref_len = 0, state = 0, quote, rc;

    /* state: -2 - syntax error,
     *        -1 - top_elem not found,
     *        0 - start,
     *        1 - parsing prefix,
     *        2 - prefix just parsed,
     *        3 - top-elem found and parsed, looking for namespace,
     *        4 - top_elem and top_elem_ns found (success)
     */

    if (!data) {
        return NULL;
    }

    while (isspace(data[0])) {
        ++data;
    }

    if (data[0] != '<') {
        return data;
    }

    for (ptr = data + 1; (ptr[0] != '\0') && (ptr[0] != '>'); ++ptr) {
        switch (state) {
        case 0:
            if (!strncmp(ptr, top_elem, strlen(top_elem))) {
                state = 3;
                ptr += strlen(top_elem);
            } else if ((ptr[0] != ':') && !isdigit(ptr[0])) {
                state = 1;
                prefix = ptr;
                pref_len = 1;
            } else {
                state = -1;
            }
            break;
        case 1:
            if (ptr[0] == ':') {
                /* prefix parsed */
                state = 2;
            } else if (ptr[0] != ' ') {
                ++pref_len;
            } else {
                state = -1;
            }
            break;
        case 2:
            if (!strncmp(ptr, top_elem, strlen(top_elem))) {
                state = 3;
                ptr += strlen(top_elem);
            } else {
                state = -1;
            }
            break;
        case 3:
            if (!strncmp(ptr, "xmlns", 5)) {
                ptr += 5;
                if (prefix) {
                    if ((ptr[0] != ':') || strncmp(ptr + 1, prefix, pref_len) || (ptr[1 + pref_len] != '=')) {
                        /* it's not the right prefix, look further */
                        break;
                    }
                    /* we found our prefix, does the namespace match? */
                    ptr += 1 + pref_len;
                }

                if (ptr[0] != '=') {
                    if (prefix) {
                        /* fail for sure */
                        state = -1;
                    } else {
                        /* it may not be xmlns attribute, but something longer... */
                    }
                    break;
                }
                ++ptr;

                if ((ptr[0] != '\"') && (ptr[0] != '\'')) {
                    state = -2;
                    break;
                }
                quote = ptr[0];
                ++ptr;

                if (strncmp(ptr, top_elem_ns, strlen(top_elem_ns))) {
                    if (prefix) {
                        state = -1;
                    }
                    break;
                }
                ptr += strlen(top_elem_ns);

                if (ptr[0] != quote) {
                    if (prefix) {
                        state = -1;
                    }
                    break;
                }

                /* success */
                ptr = strchrnul(ptr, '>');
                state = 4;
            }
            break;
        }

        if ((state < 0) || (state == 4)) {
            break;
        }
    }

    if ((state == -2) || (ptr[0] == '\0')) {
        return NULL;
    } else if (state != 4) {
        return data;
    }

    /* skip the first elem, ... */
    ++ptr;
    while (isspace(ptr[0])) {
        ++ptr;
    }
    data = ptr;

    /* ... but also its ending tag */
    if (prefix) {
        rc = asprintf(&buf, "</%.*s:%s>", pref_len, prefix, top_elem);
    } else {
        rc = asprintf(&buf, "</%s>", top_elem);
    }
    if (rc == -1) {
        return NULL;
    }

    ptr = strstr(data, buf);

    if (!ptr) {
        /* syntax error */
        free(buf);
        return NULL;
    } else {
        /* reuse it */
        prefix = ptr;
    }
    ptr += strlen(buf);
    free(buf);

    while (isspace(ptr[0])) {
        ++ptr;
    }
    if (ptr[0] != '\0') {
        /* there should be nothing more */
        return NULL;
    }

    /* ending tag and all syntax seems fine, so cut off the ending tag */
    while (isspace(prefix[-1]) && (prefix > data)) {
        --prefix;
    }
    prefix[0] = '\0';

    return data;
}

static void cli_ntf_free_data(void *user_data){
    FILE *output = user_data;

    if (output != stdout) {
        fclose(output);
    }
}

static void cli_ntf_clb(struct nc_session *UNUSED(session), const struct lyd_node *envp, const struct lyd_node *op, void *user_data){
    FILE *output = user_data;
    int was_rawmode = 0;

    if (output == stdout) {
        if (lss.rawmode) {
            was_rawmode = 1;
            linenoiseDisableRawMode(lss.ifd);
            printf("\n");
        } else {
            was_rawmode = 0;
        }
    }

    struct lyd_node *node;
    if(strcmp(op->schema->name,"synchronization-state-change") == 0){
        LY_LIST_FOR(lyd_child(op), node) {
            if (strcmp(node->schema->name, "sync-state") == 0) {
                const char *sync_state_value = lyd_get_value(node);
                printf("sync-state value: %s\n", sync_state_value);
                if(strcmp(sync_state_value, "LOCKED") == 0){
                    printf("---------> Activating the carrier\n");
                    netconf_edit_config("activate-carrier.xml");
                    exit_application = 1;
                }
                // else if ((strcmp(sync_state_value, "FREERUN") == 0) || (strcmp(sync_state_value, "HOLDOVER") == 0)){
                //     printf("---------> Deactivating the carrier\n");
                //     netconf_edit_config("deactivate-carrier.xml");
                // }
                break;
            }
        }
    }
    // fprintf(output, "notification (%s)\n", ((struct lyd_node_opaq *)lyd_child(envp))->value);
    // lyd_print_file(output, op, output_format, LYD_PRINT_WITHSIBLINGS | output_flag);
    // fprintf(output, "\n");
    fflush(output);

    if ((output == stdout) && was_rawmode) {
        linenoiseEnableRawMode(lss.ifd);
        linenoiseRefreshLine();
    }

    if (!strcmp(op->schema->name, "notificationComplete") && !strcmp(op->schema->module->name, "nc-notifications")) {
        interleave = 1;
    }
}

int my_auth_hostkey_check(const char *hostname, ssh_session session, void *priv)
{
  (void)hostname;
  (void)session;
  (void)priv;

  return 0;
}

int netconf_call_home()
{
    // oru_controller_t *oru_cont = (oru_controller_t *)arg;
    static unsigned short listening = 0;
    char *host = oru_cont.host;
    char *user = oru_cont.user;
    struct passwd *pw;
    unsigned short port = oru_cont.port;
    int timeout = oru_cont.timeout;
    int ret;
    const char *pub_key = "/home/nr5glab/.ssh/id_rsa.pub";
    const char *priv_key = "/home/nr5glab/.ssh/id_rsa";


    /* default user */
    if (!user) {
        pw = getpwuid(getuid());
        if (pw) {
            user = pw->pw_name;
        }
    }

    /* default port */
    if (!port) {
        port = NC_PORT_CH_SSH;
    }

    /* default hostname */
    if (!host) {
        host = "::0";
    }

    /* default timeout */
    if (!timeout) {
        timeout = CLI_CH_TIMEOUT;
    }

    /* Set the SSH public and private keys */
    ret = nc_client_ssh_ch_add_keypair(pub_key, priv_key);
    if (ret!=0){
	    printf("[%s] Failed to add keypairs\n", __func__);
    }
    /* create the session */
    nc_client_ssh_ch_set_username(user);
    nc_client_ssh_ch_add_bind_listen(host, port);

    nc_client_ssh_ch_set_auth_hostkey_check_clb(my_auth_hostkey_check, "DATA");  // host-key identification
    
    printf("Waiting %ds for an SSH Call Home connection on port %u with username %s...\n", timeout, port, user);
    ret = nc_accept_callhome(timeout * 1000, NULL, &session);
    nc_client_ssh_ch_del_bind(host, port);
    if (ret != 1) {
        if (ret == 0) {
            ERROR(__func__, "Receiving SSH Call Home on port %d as user \"%s\" timeout elapsed.", port, user);
        } else {
            ERROR(__func__, "Receiving SSH Call Home on port %d as user \"%s\" failed.", port, user);
        }
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int netconf_status(){
  const char *s;
  const char * const *cpblts;

  NC_TRANSPORT_IMPL transport;
  int i;

  if (!session) {
    printf("Client is not connected to any NETCONF server.\n");
  } else {
    transport = nc_session_get_ti(session);
    printf("Current NETCONF session:\n");
    printf("  ID          : %u\n", nc_session_get_id(session));
    switch (transport) {
  #ifdef NC_ENABLED_SSH
    case NC_TI_LIBSSH:
    s = "SSH";
    printf("  Host        : %s\n", nc_session_get_host(session));
    printf("  Port        : %u\n", nc_session_get_port(session));
    break;
  #endif
  #ifdef NC_ENABLED_TLS
    case NC_TI_OPENSSL:
        s = "TLS";
        printf("  Host        : %s\n", nc_session_get_host(session));
        printf("  Port        : %u\n", nc_session_get_port(session));
        break;
  #endif
    case NC_TI_FD:
        s = "FD";
        break;
    case NC_TI_UNIX:
        s = "UNIX";
        printf("  Path        : %s\n", nc_session_get_path(session));
        break;
    default:
        s = "Unknown";
        break;
  }
  printf("  Transport   : %s\n", s);
  printf("  Capabilities:\n");
  cpblts = nc_session_get_cpblts(session);
    for (i = 0; cpblts[i]; ++i) {
        printf("\t%s\n", cpblts[i]);
    }
  }

}

int netconf_get(){
    // oru_controller_t *oru_cont = (oru_controller_t *)arg;
    int c, config_fd, ret = EXIT_FAILURE, filter_param = 0, timeout = CLI_RPC_REPLY_TIMEOUT;
    struct stat config_stat;
    // char *filter = "/o-ran-sync:sync/sync-status/sync-state";
    char *filter = "/o-ran-sync:sync/sync-status";
    // char *filter = NULL; 
    char *config_m = NULL;
    struct nc_rpc *rpc;
    NC_WD_MODE wd = NC_WD_UNKNOWN;
    FILE *output = NULL;
    char *tmp_config_file = "ietf-netconf <get> operation";

    if (!session) {
        ERROR(__func__, "Not connected to a NETCONF server, no RPCs can be sent.");
        goto fail;
    }

    /* create requests */
    rpc = nc_rpc_get(filter, wd, NC_PARAMTYPE_CONST);
    if (!rpc) {
        ERROR(__func__, "RPC creation failed.");
        goto fail;
    }

    ret = cli_send_recv(rpc, stdout, wd, timeout);

    nc_rpc_free(rpc);

fail:
    // free(filter);
    return ret;
}

int netconf_subscribe(char *sub_stream){
    // oru_controller_t *oru_cont = (oru_controller_t *)arg;

    int c, config_fd, ret = EXIT_FAILURE, filter_param = 0, timeout = CLI_RPC_REPLY_TIMEOUT;
    struct stat config_stat;
    char *filter = NULL, *config_m = NULL, *start = NULL, *stop = NULL;
    // const char *stream = sub_stream;
    const char *stream = NULL;
    struct nc_rpc *rpc = NULL;
    time_t t;
    FILE *output = NULL;

    char *tmp_config_file = "notifications <create-subscription> operation";

    if (!session) {
        ERROR(__func__, "Not connected to a NETCONF server, no RPCs can be sent.");
        goto fail;
    }

    /* create requests */
    rpc = nc_rpc_subscribe(stream, filter, start, stop, NC_PARAMTYPE_CONST);
    if (!rpc) {
        ERROR(__func__, "RPC creation failed.");
        goto fail;
    }

    /* create notification thread so that notifications can immediately be received */
    if (!output) {
        output = stdout;
    }
    ret = nc_recv_notif_dispatch_data(session, cli_ntf_clb, output, cli_ntf_free_data);
    if (ret) {
        ERROR(__func__, "Failed to create notification thread.");
        goto fail;
    }
    output = NULL;

    ret = cli_send_recv(rpc, stdout, 0, timeout);
    if (ret) {
        goto fail;
    }

    if (!nc_session_cpblt(session, NC_CAP_INTERLEAVE_ID)) {
        fprintf(output, "NETCONF server does not support interleave, you\n"
                "cannot issue any RPCs during the subscription.\n"
                "Close the session with \"disconnect\".\n");
        interleave = 0;
    }

fail:
    if (output && (output != stdout)) {
        fclose(output);
    }
    free(filter);
    free(start);
    free(stop);
    nc_rpc_free(rpc);

    return ret;
}

int netconf_edit_config(const char *arg){
        int c, config_fd, ret = EXIT_FAILURE, content_param = 0, timeout = CLI_RPC_REPLY_TIMEOUT;
    struct stat config_stat;
    char *content = NULL, *config_m = NULL, *cont_start;
    NC_DATASTORE target = NC_DATASTORE_ERROR;
    struct nc_rpc *rpc;
    NC_RPC_EDIT_DFLTOP op = NC_RPC_EDIT_DFLTOP_UNKNOWN;
    NC_RPC_EDIT_TESTOPT test = NC_RPC_EDIT_TESTOPT_UNKNOWN;
    NC_RPC_EDIT_ERROPT err = NC_RPC_EDIT_ERROPT_UNKNOWN;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    target = NC_DATASTORE_RUNNING;
    op = NC_RPC_EDIT_DFLTOP_REPLACE;
     if (arg) {
        /* open edit configuration data from the file */
        config_fd = open(arg, O_RDONLY);
        if (config_fd == -1) {
            ERROR(__func__, "Unable to open the local datastore file \"%s\" (%s).", arg, strerror(errno));
            goto fail;
        }

        /* map content of the file into the memory */
        if (fstat(config_fd, &config_stat) != 0) {
            ERROR(__func__, "fstat failed (%s).", strerror(errno));
            close(config_fd);
            goto fail;
        }
        config_m = mmap(NULL, config_stat.st_size, PROT_READ, MAP_PRIVATE, config_fd, 0);
        if (config_m == MAP_FAILED) {
            ERROR(__func__, "mmap of the local datastore file failed (%s).", strerror(errno));
            close(config_fd);
            goto fail;
        }

        /* make a copy of the content to allow closing the file */
        content = strdup(config_m);

        /* unmap local datastore file and close it */
        munmap(config_m, config_stat.st_size);
        close(config_fd);
    }


    /* check if edit configuration data were specified */
    if (!content) {
        if (!content) {
            ERROR(__func__, "Reading configuration data failed.");
            goto fail;
        }
    }

    /* trim top-level element if needed */
    cont_start = trim_top_elem(content, "config", "urn:ietf:params:xml:ns:netconf:base:1.0");
    if (!cont_start) {
        ERROR(__func__, "Provided configuration content is invalid.");
        goto fail;
    }

    rpc = nc_rpc_edit(target, op, test, err, cont_start, NC_PARAMTYPE_CONST);
    if (!rpc) {
        ERROR(__func__, "RPC creation failed.");
        goto fail;
    }

    ret = cli_send_recv(rpc, stdout, 0, timeout);

    nc_rpc_free(rpc);

fail:
    free(content);
    return ret;
}

static int
cmd_disconnect(const char *UNUSED(arg), char **UNUSED(tmp_config_file))
{
    if (session == NULL) {
        ERROR("disconnect", "Not connected to any NETCONF server.");
    } else {
        nc_session_free(session, NULL);
        session = NULL;
    }

    return EXIT_SUCCESS;
}