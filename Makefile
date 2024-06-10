all:
	gcc -o netconf_client netconf_client.c -lnetconf2 -lssh -lxml2 -lyang
clean:
	rm -rf netconf_client
