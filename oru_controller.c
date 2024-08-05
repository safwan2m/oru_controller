/**
 * @file sr_get_items_example.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief example of an application that gets values
 *
 * @copyright
 * Copyright (c) 2019 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#define _GNU_SOURCE

#include "oru_controller_api/oru_controller_api.h"
#include "netconf_cli_api/netconf_cli_api.h"
#include "sysrepo_api/sysrepo_api.h"

extern struct nc_session *session;

int done;
volatile int exit_application = 0;

oru_controller_t oru_cont;

static void sigint_handler(int signum) {
    (void)signum;

    exit_application = 1;
}

static void print_val(const sr_val_t *value) {
}

int main(int argc, char **argv) {

    printf("Starting O-RU controller program\n");
    char *user = "root";
    char *stream = "o-ran-sync";

    // oru_cont = (oru_controller_t *)malloc(sizeof(oru_controller_t));
    
    oru_cont.user = user;
    oru_cont.timeout = -1;
    
    oru_cont.ds = SR_DS_RUNNING;
    sysrepo_connect();
    sysrepo_get_data();

    
    if(netconf_call_home()){
	   printf("Callhome successful for user %s\n",oru_cont.user);
    }

    netconf_status();

    netconf_get();

    netconf_subscribe(stream);
    // netconf_subscribet);
    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, SIG_IGN);
    while(!exit_application){
    }
    printf("Done!\n");
}
