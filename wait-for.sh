#!/usr/bin/env sh

ARGUMENT=$1
shift
CMD="$@"

HOST="$(echo $ARGUMENT | cut -d ':' -f1)"
PORT="$(echo $ARGUMENT | cut -d ':' -f2)"
MAX_RETRY=90

echo "Testing connection to host $HOST and port $PORT."

count=0
while [ $count -lt $MAX_RETRY ]
do
    count=$((count+1))
    nc -z $HOST $PORT
    result=$?
    if [ $result -eq 0 ]; then
        echo "Connection is available after $count second(s)."
        echo "Starting $CMD."
        exec $CMD
    fi
    echo "Retrying..."
    sleep 1
done

>&2 echo "Timeout occurred after waiting $MAX_RETRY seconds for $HOST:$PORT."
exit 1