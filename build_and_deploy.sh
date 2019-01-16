#!/bin/bash
#

GUNICORN_PORT=9000
HTTP_PORT=10000


start() {
    cd frontend && npm run build
    cd ..
    cp frontend/dist/index.html templates/login.html
    cp -r frontend/dist/static/* static/
    gunicorn --access-logfile - -b "127.0.0.1:$GUNICORN_PORT" authenticator.wsgi  --daemon
    sudo caddy -http-port $HTTP_PORT
}

kill_cmd() {
    pkill gunicorn
}

stop() {
    kill_cmd
}

case "$1" in
    'start')
            start
            ;;
    'stop')
            stop
            ;;
    'restart')
            stop ; echo "Sleeping..."; sleep 1 ;
            start
            ;;
    'status')
            status
            ;;
    *)
            echo
            echo "Usage: $0 { start | stop | restart | status }"
            echo
            exit 1
            ;;
esac

exit 0


