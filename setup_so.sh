#!/bin/bash

dir=`pwd`

echo -n "MISP IP: "
read ip

echo -n "Server port: "
read port

cp $dir/filter_backup $dir/filter.py
sed -i "s/MISP_LOCATION/'$ip'/;s/MISP_PORT/$port/" $dir/filter.py

echo -n "Scheduling cronjob"
crontab -l > cronlist 2>/dev/null
echo "* * * * * python3 $dir/filter.py" >> cronlist
crontab cronlist 2>/dev/null
rm cronlist
printf "\n"
