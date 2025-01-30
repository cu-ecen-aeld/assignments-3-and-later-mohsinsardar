#!/bin/sh

# Description: Startup script for aesdsocket daemon


case "$1" in
    start)
		echo "Starting aesdsocket server"
        # Start aesdsocket as a daemon
        start-stop-daemon -S -n aesdsocket -a /usr/bin/aesdsocket -- -d
        ;;
    stop)
		echo "Stopping aesdsocket server"
        # Stop aesdsocket gracefully with SIGTERM
        start-stop-daemon -K -n aesdsocket
        ;;
    *)
        echo "Usage: $0 {start|stop}"
		exit 1
        ;;
esac

exit 0
