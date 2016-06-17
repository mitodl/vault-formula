#!/bin/bash

PIDFILE=/var/run/vault.pid

start () {
    /usr/local/bin/vault server -config /etc/vault 2>&1 &
    echo $! > $PIDFILE
    echo "Vult is starting"
}

stop () {
    if [ -e $PIDFILE ]
    then
        /bin/kill $(cat $PIDFILE)
        echo "Stopping Vault"
    else
        echo 'Vault is not running'
    fi
}

reload () {
    if [ -e $PIDFILE ]
    then
        /bin/kill -1 $(cat $PIDFILE)
        echo "Vault reloaded"
    else
        echo 'Vault is not running'
    fi
}

case $1 in
    start)
        start
        ;;
    stop)
        stop
        ;;
    reload)
        reload
        ;;
    restart)
        stop
        sleep 1
        start
        ;;
    *) exit 1
esac
