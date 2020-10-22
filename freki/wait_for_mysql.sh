#!/bin/sh

while ! mysqladmin ping -h"db" -P"3306" --silent; do
    echo "Waiting for MySQL to be up..."
    sleep 1
done

sleep 3
echo "Starting Freki..."
sleep 4
mysql --host=192.168.99.98 --user=freki --password=qwer1234 < data.sql

echo "ingresando datos"
exit 0