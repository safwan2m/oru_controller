#include <stdio.h>
#include <stdlib.h>
#include <libnetconf2/session_client.h>
#include <libyang/libyang.h>

#define CALLHOME_TIMEOUT -1

void print_error(struct nc_session *session) {
    const char *message, *message2, *severity;
    nc_err_get_msg(session, &message, &message2, &severity);
    printf("Error: %s %s %s\n", message, message2, severity);
}

int main() {
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

    // Accept callhome message from RU
    // nc_accept_callhome(CALLHOME_TIMEOUT, NULL, &session);
    // Create and configure the session
    session = nc_connect_ssh(host, port, ctx);
    if (!session) {
        fprintf(stderr, "Failed to connect to %s:%d\n", host, port);
        ly_ctx_destroy(ctx);
        nc_client_destroy();
        return EXIT_FAILURE;
    }

    // Authenticate the user
    // if (nc_ssh_userauth_password(session, username, "your_password") != NC_RPL_OK) { // Replace with your password
    //     fprintf(stderr, "Authentication failed\n");
    //     print_error(session);
    //     nc_session_free(session, NULL);
    //     ly_ctx_destroy(ctx);
    //     nc_client_destroy();
    //     return EXIT_FAILURE;
    // }

    // Now you are connected and authenticated, you can perform NETCONF operations

    printf("Connected to %s:%d as %s\n", host, port, username);

    // Clean up and close the session
    // nc_session_free(session, NULL);
    ly_ctx_destroy(ctx);
    nc_client_destroy();

    return EXIT_SUCCESS;
}

