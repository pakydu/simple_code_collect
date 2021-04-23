#/bin/bash

###########################################
#检查网卡流量，按规定格式记录在日志中
#规定一分钟记录一次
#日志格式如下：
#2021-01-01 12：10
#eth0 input 100bps
#eth0 output 200bps
#######################################################


while:
do 
    LANG=en
    logfile=/tmp/`date +%d`.log
    exec >> $logfile
    date +"%F %H:%M"

    #use sar tool to get the data
    sar -n DEV 1 59 | grep Average|grep eth0|awk '{print $2, "\t", "input:", "\t",%5*1000*8,"bps","\n",$2,"\t","output:", "\t",$6*1000*8,"bps"}'
    echo "######################################"
done