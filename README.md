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
