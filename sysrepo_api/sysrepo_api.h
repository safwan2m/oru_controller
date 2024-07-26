#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "sysrepo.h"

#include "oru_controller_api.h"

extern oru_controller_t oru_cont;

int sysrepo_connect();

int sysrepo_get();
