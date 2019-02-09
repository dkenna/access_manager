#!/bin/bash
#

APP="authenticator"

GUNICORN_APP="${APP}_gunicorn"
CADDY_APP="${APP}_caddy"

GUNICORN_PID=/tmp/${GUNICORN_APP}.pid
GUNICORN_LOG=/tmp/${GUNICORN_APP}.log
GUNICORN_ERROR=/tmp/${GUNICORN_APP}-error.log
GUNICORN_ACCESS=/tmp/${GUNICORN_APP}-access.log

CADDY_PID=/tmp/$CADDY_APP.pid
CADDY_LOG=/tmp/${CADDY_APP}.log

GUNICORN_PORT=9000
HTTP_PORT=10000

GUNICORN_CMD="../bin/gunicorn --access-logfile $GUNICORN_ACCESS -b "127.0.0.1:$GUNICORN_PORT" -p $GUNICORN_PID authenticator.wsgi --daemon"
CADDY_CMD="sudo caddy -http-port $HTTP_PORT  -pidfile=$CADDY_PID"

status() {
    PID=${1}_PID
    echo
    echo "==== Status"

    if [ -f ${!PID} ]
    then
        echo
        echo "Pid file: $( cat ${!PID} ) [${!PID}]"
        echo
        ps -ef | grep -v grep | grep $( cat ${!PID} )
    else
        echo
        echo "No Pid file"
    fi
}

kill_cmd() {
    PID=${1}_PID
    CMD=${1}_CMD
    SIGNAL=""; MSG="Killing ${1} "
    while true
    do
        LIST=`ps -ef | grep -v grep | grep ${APP} | awk '{print $2}'`
        if [ "$LIST" ]
        then
            echo; echo "$MSG $LIST" ; echo
            echo $LIST | xargs sudo kill $SIGNAL
            sleep 2
            SIGNAL="-9" ; MSG="Killing $SIGNAL"
            if [ -f ${!PID} ]
            then
                /bin/rm ${!PID}
            fi
        else
           echo; echo "All killed..." ; echo
           break
        fi
    done
}

stop() {
    PID=${1}_PID
    CMD=${1}_CMD
    LOG=${1}_LOG
    echo "==== Stopping ${1}"

    if [ -f ${!PID} ]
    then
        if sudo kill $( cat ${!PID} )
        then echo "Done."
             echo "$(date '+%Y-%m-%d %X'): STOP" >>${!LOG}
        fi
        /bin/rm ${!PID}
        kill_cmd $1
    else
        echo "No pid file. Already stopped?"
    fi
}
build() {
    cd frontend && npm run build
    cd ..
    cp frontend/dist/index.html templates/login.html
    cp -r frontend/dist/static/* static/
}
start() {
    PID=${1}_PID
    CMD=${1}_CMD
    LOG=${1}_LOG
    stop $1
    if [ -f ${!PID} ]
        then
            echo
            echo "${1}: Already started. PID: [$( cat ${!PID} )]"
        else
            echo "==== Start"
            touch ${!PID}
            echo "${!CMD}"
            if nohup ${!CMD} &
            then echo $! >${!PID}
                echo "Done.${!LOG}"
                echo "$(date '+%Y-%m-%d %X'): START" >>${!LOG}
            else echo "Error... "
                /bin/rm ${!PID}
            fi
    fi
}

case "$1" in
    'build')
            build
            ;;
    'start')
            start "GUNICORN"
            start "CADDY"
            ;;
    'stop')
            stop "GUNICORN"
            stop "CADDY"
            ;;
    'restart')
            stop ; echo "Sleeping..."; sleep 1 ;
            start
            ;;
    'status')
            status "GUNICORN"
            status "CADDY"
            ;;
    *)
            echo
            echo "Usage: $0 { start | stop | restart | status }"
            echo
            exit 1
            ;;
esac

exit 0


