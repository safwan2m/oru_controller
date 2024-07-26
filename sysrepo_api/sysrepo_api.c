#include "sysrepo_api.h"
#include "oru_controller_api.h"

extern LYD_FORMAT output_format;

int sysrepo_connect(){
	
    // sr_conn_ctx_t *connection = oru_cont.connection;

    int rc = SR_ERR_OK;
    // const char *xpath;
    // const char *op_str;
    // sr_val_t *vals = NULL;
    // size_t i, val_count = 0;

    // sr_datastore_t ds = SR_DS_RUNNING;
    sr_datastore_t ds = oru_cont.ds;

    /* turn logging on */
    sr_log_stderr(SR_LL_WRN);

    /* connect to sysrepo */
    rc = sr_connect(0, &oru_cont.connection);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* start session */
    rc = sr_session_start(oru_cont.connection, ds, &oru_cont.session);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    // sysrepo_get_data();
    return rc ? EXIT_FAILURE : EXIT_SUCCESS;
cleanup:
    sr_disconnect(oru_cont.connection);
}

int sysrepo_get_data(){
    // oru_controller_t *oru_cont = (oru_controller_t *)arg;
    // sr_session_ctx_t *sess = oru_cont->session;
    
    uint32_t max_depth = 0; 
    int wd_opt = LYD_PRINT_WD_ALL; 
    int timeout_s = 0;

    const char *xpath = NULL;
    const char *module_name = NULL;
    const char *file_path = NULL;

    sr_data_t *data;
    FILE *file = NULL;
    char *str;
    int r;

    if (file_path) {
        file = fopen(file_path, "w");
        if (!file) {
            printf("Failed to open \"%s\" for writing (%s)", file_path, strerror(errno));
            return EXIT_FAILURE;
        }
    }

    /* get subtrees */
    r = sr_get_data(oru_cont.session, "/*", max_depth, timeout_s * 1000, 0, &data);
    if (r != SR_ERR_OK) {
        printf("Getting data failed");
        if (file) {
            fclose(file);
        }
        return EXIT_FAILURE;
    }

    /* print exported data */
    lyd_print_file(file ? file : stdout, data ? data->tree : NULL, output_format, LYD_PRINT_WITHSIBLINGS | wd_opt);
    sr_release_data(data);

    /* cleanup */
    if (file) {
        fclose(file);
    }
}
