#!/bin/bash
netopeer2-cli <<END
listen --ssh --login oranuser
status
disconnect
quit
END
echo ""
exit 0
get-config --source running --out out.xml
connect --host 192.168.4.24 --login oranuser
