# tpm2-ssh-agent
SSH agent using TPM 2.0

# Example setup
```
$ tpm2_createprimary -H o -g sha256 -G ecc
ObjectAttribute: 0x00030072

CreatePrimary Succeed ! Handle: 0x80000000


$ tpm2_create -H 0x80000000 -g sha256 -G rsa -u public -r private
algorithm:
  value: sha256
  raw: 0xb
attributes:
  value: fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt|sign
  raw: 0x60072
type: 
  value: rsa
  raw: 0x1
  rsa: .....
$ cat public private > rsa-key
$ tpm2-ssh-agent --socket /tmp/test.socket --key rsa-key -f
```
And to check that it works
```
$ SSH_AUTH_SOCK=/tmp/test.socket ssh-add -L
ssh-rsa AAAA....
```
