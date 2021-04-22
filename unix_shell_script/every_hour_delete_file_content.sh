#/bin/bash

#################################################
#define function to delete file context every hour
#This scrip didn't use linux crontab
#################################################

logfile=/tmp/`date +%H-%F`.log
n=`date +%H`

if [ $n -eq 00 ] || [ $n -eq 12 ]; then
    for i in `find /var/log/ -type f`
    do
        true > $i
    done
else
    for i in `find /var/log/ -type f`
    do
        du -sh $i >> $logfile
    done
fi
