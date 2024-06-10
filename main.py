from ncclient import manager

with manager.connect(host='127.0.0.1', port=830, username='nr5glab', hostkey_verify=False) as m:
    c = m.get_config(source='running').data_xml
    with open("%s.xml" % host, 'w') as f:
        f.write(c)
