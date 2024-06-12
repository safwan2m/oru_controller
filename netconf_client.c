#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/times.h>
#include <sys/types.h>
#include <unistd.h>

#include <libyang/libyang.h>
#include <nc_client.h>

#include "commands.h"
#include "compat.h"
#include "completion.h"
#include "configuration.h"
#include "linenoise/linenoise.h"
#define NC_PORT_CH_SSH 4334
#define CLI_CH_TIMEOUT -1

int done;

extern char *config_editor;
extern struct nc_session *session;

void
lnc2_print_clb(NC_VERB_LEVEL level, const char *msg)
{
    int was_rawmode = 0;

    if (lss.rawmode) {
        was_rawmode = 1;
        linenoiseDisableRawMode(lss.ifd);
        printf("\n");
    }

    switch (level) {
    case NC_VERB_ERROR:
        fprintf(stderr, "nc ERROR: %s\n", msg);
        break;
    case NC_VERB_WARNING:
        fprintf(stderr, "nc WARNING: %s\n", msg);
        break;
    case NC_VERB_VERBOSE:
        fprintf(stderr, "nc VERBOSE: %s\n", msg);
        break;
    case NC_VERB_DEBUG:
    case NC_VERB_DEBUG_LOWLVL:
        fprintf(stderr, "nc DEBUG: %s\n", msg);
        break;
    }

    if (was_rawmode) {
        linenoiseEnableRawMode(lss.ifd);
        linenoiseRefreshLine();
    }
}

void
ly_print_clb(LY_LOG_LEVEL level, const char *msg, const char *path)
{
    int was_rawmode = 0;

    if (lss.rawmode) {
        was_rawmode = 1;
        linenoiseDisableRawMode(lss.ifd);
        printf("\n");
    }

    switch (level) {
    case LY_LLERR:
        if (path) {
            fprintf(stderr, "ly ERROR: %s (%s)\n", msg, path);
        } else {
            fprintf(stderr, "ly ERROR: %s\n", msg);
        }
        break;
    case LY_LLWRN:
        if (path) {
            fprintf(stderr, "ly WARNING: %s (%s)\n", msg, path);
        } else {
            fprintf(stderr, "ly WARNING: %s\n", msg);
        }
        break;
    case LY_LLVRB:
        if (path) {
            fprintf(stderr, "ly VERBOSE: %s (%s)\n", msg, path);
        } else {
            fprintf(stderr, "ly VERBOSE: %s\n", msg);
        }
        break;
    case LY_LLDBG:
        if (path) {
            fprintf(stderr, "ly DEBUG: %s (%s)\n", msg, path);
        } else {
            fprintf(stderr, "ly DEBUG: %s\n", msg);
        }
        break;
    default:
        /* silent, just to cover enum, shouldn't be here in real world */
        return;
    }

    if (was_rawmode) {
        linenoiseEnableRawMode(lss.ifd);
        linenoiseRefreshLine();
    }
}

void print_error(struct nc_session *session) {
    const char *message, *message2, *severity;
    nc_err_get_msg(session, &message, &message2, &severity);
    printf("Error: %s %s %s\n", message, message2, severity);
}

static int call_home(void *arg){
	struct nc_session *session = NULL;
	char *username = "oranuser";
	int timeout, port = 4334;

        /* default hostname */
        char *host = "::0";


        /* default timeout */
        if (!timeout) {
            timeout = CLI_CH_TIMEOUT;
        }

        /* create the session */
        nc_client_ssh_ch_set_username(username);
        nc_client_ssh_ch_add_bind_listen(host, port);
        printf("Waiting %ds for an SSH Call Home connection on port %u...\n", timeout, port);

        int ret = nc_accept_callhome(timeout * 1000, NULL, &session);
        nc_client_ssh_ch_del_bind(host, port);
        if (ret != 1) {
            if (ret == 0) {
                printf("[%s] Receiving SSH Call Home on port %d as user \"%s\" timeout elapsed.", __func__, port, username);
            } else {
                printf("[%s] Receiving SSH Call Home on port %d as user \"%s\" failed.", __func__, port, username);
            }
            return EXIT_FAILURE;
        }

	if(ret == 1)printf("Callhome successfull\n");

	nc_session_free(session, NULL);

}

int connet_thread(void *arg){
    struct nc_session *session;
    const char *host = "192.168.4.24";
    const char *username = "root"; // Replace with your username
    unsigned short port = 830;

    // Initialize libnetconf2
    nc_client_init();

    // Load libyang context (required for libnetconf2)
    struct ly_ctx *ctx; 
    ly_ctx_new(NULL, 0, &ctx);
    if (!ctx) {
        fprintf(stderr, "Failed to create ly_ctx\n");
        nc_client_destroy();
        return EXIT_FAILURE;
    }
    // Set SSH username
    int ret = nc_client_ssh_set_username(username);

    // Create and configure the session
    session = nc_connect_ssh(host, port, ctx);

    if (!session) {
        fprintf(stderr, "Failed to connect to %s:%d\n", host, port);
        ly_ctx_destroy(ctx);
        nc_client_destroy();
        return EXIT_FAILURE;
    }

    printf("Connected to %s:%d as %s\n", host, port, username);

    // Clean up and close the session
    // nc_session_free(session, NULL);
    ly_ctx_destroy(ctx);
    nc_client_destroy();

    return EXIT_SUCCESS;
}

int main() {

    char *cmd, *cmdline, *cmdstart, *tmp_config_file = NULL;
    int i, j;
    struct sigaction action;

    nc_client_init();

    /* ignore SIGPIPE */
    memset(&action, 0, sizeof action);
    action.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &action, NULL);

    nc_set_print_clb(lnc2_print_clb);
    ly_set_log_clb(ly_print_clb, 1);
    linenoiseSetCompletionCallback(complete_cmd);
    linenoiseHistoryDataFree(free);

    load_config();

    if (!config_editor) {
        config_editor = getenv("EDITOR");
        if (config_editor) {
            config_editor = strdup(config_editor);
        }
    }
    if (!config_editor) {
        config_editor = strdup("vi");
    }
    char *list[] ={"listen --ssh --login oranuser","status","quit","get"};
    int numCmds = sizeof(list)/ sizeof(list[0]);

    // while (!done) {
    for(int i=0; i<numCmds; i++){
        /* get the command from user */
        // cmdline = linenoise(PROMPT);
        cmdline = strdup(list[i]); 
	printf("Executing cmd \"%s\"\n",cmdline);

        /* isolate the command word. */
        for (i = 0; cmdline[i] && (cmdline[i] == ' '); i++) {}
        cmdstart = cmdline + i;
        for (j = 0; cmdline[i] && (cmdline[i] != ' '); i++, j++) {}
        cmd = strndup(cmdstart, j);

        /* parse the command line */
        for (i = 0; commands[i].name; i++) {
            if (strcmp(cmd, commands[i].name) == 0) {
                break;
            }
        }

        /* execute the command if any valid specified */
        if (commands[i].name) {
            /* display help */
            if ((strchr(cmdstart, ' ') != NULL) && ((strncmp(strchr(cmdstart, ' ') + 1, "-h", 2) == 0) ||
                    (strncmp(strchr(cmdstart, ' ') + 1, "--help", 6) == 0))) {
                if (commands[i].help_func != NULL) {
                    commands[i].help_func();
                } else {
                    printf("%s\n", commands[i].helpstring);
                }
            } else {
                if (lss.history_index) {
                    tmp_config_file = (char *)lss.history[lss.history_len - lss.history_index].data;
                }
                commands[i].func((const char *)cmdstart, &tmp_config_file);
            }
        } else {
            /* if unknown command specified, tell it to user */
            fprintf(stderr, "%s: No such command, type 'help' for more information.\n", cmd);
        }
        if (!done) {
            linenoiseHistoryAdd(cmdline, tmp_config_file);
        }

        tmp_config_file = NULL;
    }

    {

        cmdline = strdup(list[1]); 
	printf("Executing cmd \"%s\"\n",cmdline);

        /* isolate the command word. */
        for (i = 0; cmdline[i] && (cmdline[i] == ' '); i++) {}
        cmdstart = cmdline + i;
        for (j = 0; cmdline[i] && (cmdline[i] != ' '); i++, j++) {}
        cmd = strndup(cmdstart, j);

        /* parse the command line */
        for (i = 0; commands[i].name; i++) {
            if (strcmp(cmd, commands[i].name) == 0) {
                break;
            }
        }

        /* execute the command if any valid specified */
        if (commands[i].name) {
            /* display help */
            if ((strchr(cmdstart, ' ') != NULL) && ((strncmp(strchr(cmdstart, ' ') + 1, "-h", 2) == 0) ||
                    (strncmp(strchr(cmdstart, ' ') + 1, "--help", 6) == 0))) {
                if (commands[i].help_func != NULL) {
                    commands[i].help_func();
                } else {
                    printf("%s\n", commands[i].helpstring);
                }
            } else {
                if (lss.history_index) {
                    tmp_config_file = (char *)lss.history[lss.history_len - lss.history_index].data;
                }
                commands[i].func((const char *)cmdstart, &tmp_config_file);
            }
        } else {
            /* if unknown command specified, tell it to user */
            fprintf(stderr, "%s: No such command, type 'help' for more information.\n", cmd);
        }
        if (!done) {
            linenoiseHistoryAdd(cmdline, tmp_config_file);
        }

        tmp_config_file = NULL;
    }

    {

        cmdline = strdup(list[3]); 
	printf("Executing cmd \"%s\"\n",cmdline);

        /* isolate the command word. */
        for (i = 0; cmdline[i] && (cmdline[i] == ' '); i++) {}
        cmdstart = cmdline + i;
        for (j = 0; cmdline[i] && (cmdline[i] != ' '); i++, j++) {}
        cmd = strndup(cmdstart, j);

        /* parse the command line */
        for (i = 0; commands[i].name; i++) {
            if (strcmp(cmd, commands[i].name) == 0) {
                break;
            }
        }

        /* execute the command if any valid specified */
        if (commands[i].name) {
            /* display help */
            if ((strchr(cmdstart, ' ') != NULL) && ((strncmp(strchr(cmdstart, ' ') + 1, "-h", 2) == 0) ||
                    (strncmp(strchr(cmdstart, ' ') + 1, "--help", 6) == 0))) {
                if (commands[i].help_func != NULL) {
                    commands[i].help_func();
                } else {
                    printf("%s\n", commands[i].helpstring);
                }
            } else {
                if (lss.history_index) {
                    tmp_config_file = (char *)lss.history[lss.history_len - lss.history_index].data;
                }
                commands[i].func((const char *)cmdstart, &tmp_config_file);
            }
        } else {
            /* if unknown command specified, tell it to user */
            fprintf(stderr, "%s: No such command, type 'help' for more information.\n", cmd);
        }
        if (!done) {
            linenoiseHistoryAdd(cmdline, tmp_config_file);
        }

        tmp_config_file = NULL;
    }

    store_config();

    free(config_editor);

    if (session) {
        nc_session_free(session, NULL);
    }

    nc_client_destroy();

    return 0;

}

