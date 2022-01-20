project('tpm2-ssh-agent', 'c',
  version : '0.1',
  default_options : ['warning_level=3'])

dependencies = [dependency('tss2-esys'), dependency('tss2-mu'), dependency('libcrypto')]
systemd_dep = dependency('libsystemd', required: false)

if systemd_dep.found()
  add_global_arguments('-DWITH_SYSTEMD', language : 'c')
endif
  
    
executable('tpm2-ssh-agent',
           'socket.c',
           'log.c',
           'main.c',
           'message.c',
           'list.c',
           'keys.c',
           'buffer.c',
           'sign.c',
           install : true,
	   dependencies : [dependencies, systemd_dep],
	  )
