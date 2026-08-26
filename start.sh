#!/bin/sh
set -e

/app/server &
BACKEND_PID=$!

nginx -g "daemon off;" &
NGINX_PID=$!

wait -n $BACKEND_PID $NGINX_PID
exit $?