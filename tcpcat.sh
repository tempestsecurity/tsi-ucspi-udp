exec HOME/bin/udpconnect -RHl0 -- "${1-0}" "${2-17}" sh -c 'exec cat <&6'
