#
# Regular cron jobs for the tpm2-ssh-agent package.
#
0 4	* * *	root	[ -x /usr/bin/tpm2-ssh-agent_maintenance ] && /usr/bin/tpm2-ssh-agent_maintenance
