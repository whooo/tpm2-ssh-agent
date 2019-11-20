# tpm2-ssh-agent
SSH agent using TPM 2.0

# Example setup
```
$ tpm2_createprimary -C o -c primary.ctx -g sha256 -G ecc
name-alg:
  value: sha256
  raw: 0xb
...

$ tpm2_create -C primary.ctx -g sha256 -G rsa -u public -r private
name-alg:
  value: sha256
  raw: 0xb
...

$ cat public private > rsa-key
$ tpm2-ssh-agent --socket /tmp/test.socket --key rsa-key -f
```
And to check that it works
```
$ SSH_AUTH_SOCK=/tmp/test.socket ssh-add -L
ssh-rsa AAAA....
```

# Example ssh hostkey setup using OpenRC scripts
* Create key and store it
```
# tpm2_createprimary -C o -c primary.ctx -g sha256 -G ecc
# tpm2_create -C primary.ctx -g sha256 -G rsa -u public -r private
# cat public private > /etc/ssh/ssh_hostagent_rsa_key.tpm
```

* Configure tpm2-ssh-agent
Change /etc/conf.d/tpm2-ssh-agent to it contains the key
It is done by setting the path in tpm2_ssh_agent_keyfiles
```
# Configuration for /etc/init.d/tpm2-ssh-agent

# Options to pass to tpm2-ssh-agent
#tpm2_ssh_agent_opts=""

# Path for socket
tpm2_ssh_agent_socket="/run/tpm2_ssh_agent.socket"

# Space seperated list of key files
tpm2_ssh_agent_keyfiles="/etc/ssh/ssh_hostagent_rsa_key.tpm"

# Space seperated list of key handles
#tpm2_ssh_agent_keyhandles=""
```

* Enable and start the service
```
# rc-update add tpm2-ssh-agent
# service tpm2-ssh-agent start
```

* Get the public in ssh format
```
# SSH_AUTH_SOCK=/run/tpm2_ssh_agent.socket ssh-add -L
```
Store the output in /etc/ssh/ssh_hostagent_rsa_key

* Configure sshd
Add the following lines after the "HostKey ..." lines
```
HostKey /etc/ssh/ssh_hostagent_rsa_key
HostKeyAgent /run/tpm2_ssh_agent.socket
```
Disable the other HostKey lines by commenting them with '#'

* Restart sshd
```
# service sshd restart
```

* Verify that sshd uses the key
Run ssh-keyscan to get the public key
```
# ssh-keyscan -t rsa localhost
# localhost:22 SSH-2.0-OpenSSH_8.1
localhost ssh-rsa AAAA...
```
Check that the key from ssh-keyscan is the same in /etc/ssh/ssh_hostagent_rsa_key

If nothing failed your ssh daemon should now use your TPM key!
