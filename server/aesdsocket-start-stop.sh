#! /bin/sh
set -e

case "$1" in
    start)
        echo "Starting simpleserver"
        start-stop-daemon --start --quiet -n aesdsocket --exec /usr/bin/aesdsocket -- "-d"
        ;;
    stop)
        echo "Stopping simpleserver"
        start-stop-daemon --stop --quiet --oknodo -n aesdsocket
        ;;
    *)
        echo "Usage: $0 {start|stop}"
    exit 1
esac
exit 0
        
