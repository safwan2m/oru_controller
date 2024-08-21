#include"netconf_cli_api.h"

enum sync_state{
    FREERUN,
    HOLDOVER,
    LOCKED,

}sync_state_var;
char old_state[10], new_state[10];

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

extern struct nc_session *session;
extern LYD_FORMAT output_format;
extern uint32_t output_flag;
extern volatile int interleave;

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
                }
                else if ((strcmp(sync_state_value, "FREERUN") == 0) || (strcmp(sync_state_value, "HOLDOVER") == 0)){
                    printf("---------> Deactivating the carrier\n");
                    netconf_edit_config("deactivate-carrier.xml");
                }
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
    char *filter = NULL; 
    char *config_m = NULL;
    struct nc_rpc *rpc;
    NC_WD_MODE wd = NC_WD_UNKNOWN;
    FILE *output = NULL;
    char *tmp_config_file = "ietf-netconf <get> operation";

    if (!session) {
        ERROR(__func__, "Not connected to a NETCONF server, no RPCs can be sent.");
        goto fail;
    }

    /* check if edit configuration data were specified */
    if (filter_param && !filter) {
        /* let user write edit data interactively */
        filter = readinput("Type the content of the subtree filter.", *tmp_config_file, tmp_config_file);
        if (!filter) {
            ERROR(__func__, "Reading filter data failed.");
            goto fail;
        }
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

    /* check if edit configuration data were specified */
    if (filter_param && !filter) {
        /* let user write edit data interactively */
        filter = readinput("Type the content of the subtree filter.", *tmp_config_file, tmp_config_file);
        if (!filter) {
            ERROR(__func__, "Reading filter data failed.");
            goto fail;
        }
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
        /* let user write edit data interactively */
        // content = readinput("Type the content of the <edit-config>.", *tmp_config_file, tmp_config_file);
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