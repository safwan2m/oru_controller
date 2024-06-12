all:
	gcc -o netconf_client netconf_client.c cli/commands.c cli/completion.c cli/configuration.c cli/linenoise/linenoise.c compat/compat.c -Wl,-rpath,/usr/local/lib: /usr/local/lib/libyang.so /usr/local/lib/libnetconf2.so /usr/local/lib/libssh.so -lssl -lcrypto -I/home/nr5glab/test/netconf_test/compat -I/home/nr5glab/test/netconf_test/cli -DHAVE_MKSTEMPS
clean:
	rm -rf netconf_client
