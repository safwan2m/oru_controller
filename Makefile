all: oru_controller
	echo "done"
oru_controller: oru_controller.c sysrepo_api/sysrepo_api.c netconf_cli_api/netconf_cli_api.c
	gcc -o oru_controller oru_controller.c sysrepo_api/sysrepo_api.c netconf_cli_api/netconf_cli_api.c cli/commands.c cli/completion.c cli/configuration.c cli/linenoise/linenoise.c compat/compat.c -Wl,-rpath,/usr/local/lib: /usr/local/lib/libyang.so /usr/local/lib/libnetconf2.so /usr/local/lib/libssh.so -lssl -lcrypto -I/home/nr5glab/test/oru_controller/compat -I/home/nr5glab/test/oru_controller/cli -DHAVE_MKSTEMPS -lsysrepo -lyang -I/home/nr5glab/test/oru_controller/sysrepo_api -I/home/nr5glab/test/oru_controller/oru_controller_api -I/home/nr5glab/test/oru_controller/netconf_cli_api -I/opt/dev/install/sysrepo/src -g -lxml2
clean:
	rm -rf oru_controller
