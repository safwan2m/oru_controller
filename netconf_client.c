#include <stdio.h>
#include <stdlib.h>
#include <libnetconf2/session_client.h>
#include <libyang/libyang.h>

#define NC_PORT_CH_SSH 4334
#define CLI_CH_TIMEOUT -1

void print_error(struct nc_session *session) {
    const char *message, *message2, *severity;
    nc_err_get_msg(session, &message, &message2, &severity);
    printf("Error: %s %s %s\n", message, message2, severity);
}

static void *call_home_thread(void *arg){
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

void *connet_thread(void *arg){
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

	call_home_thread(NULL);
}

