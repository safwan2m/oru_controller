#include"netconf_cli_api.h"

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

    fprintf(output, "notification (%s)\n", ((struct lyd_node_opaq *)lyd_child(envp))->value);
    lyd_print_file(output, op, output_format, LYD_PRINT_WITHSIBLINGS | output_flag);
    fprintf(output, "\n");
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

int netconf_subscribe(){
    // oru_controller_t *oru_cont = (oru_controller_t *)arg;

    int c, config_fd, ret = EXIT_FAILURE, filter_param = 0, timeout = CLI_RPC_REPLY_TIMEOUT;
    struct stat config_stat;
    char *filter = NULL, *config_m = NULL, *start = NULL, *stop = NULL;
    const char *stream = "o-ran-sync";
    struct nc_rpc *rpc = NULL;
    time_t t;
    FILE *output = NULL;
    int option_index = 0;

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
