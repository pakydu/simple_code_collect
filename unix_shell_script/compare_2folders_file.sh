#/bin/bash

###########################################
#Check the two PCs' folder files. 
#Try to make sure they are the same or not.
#We use the file's md5 to identify
###########################################

dir=/www/
b_ip=192.168.1.250

#check all of the file which belongs to the targit folder:
find  $dir -type f | xargs md5sum > /tmp/md5_a.txt

ssh $b_ip "find $dir -type -f | xargs md5sum > /tmp/md5_b.txt"
scp $b_ip:/tmp/md5_b.txt /tmp/

#now we can check the result:
for f in `awk '{print 2} /tmp/md5_a.txt'`
do
    if grep -qw "$f" /tmp/md5_b.txt
    then
        md5_a=`grep -w "$f" /tmp/md5_a.txt | awk '{print 1}'`
        md5_b=`grep -w "$f" /tmp/md5_b.txt | awk '{print 1}'`
        if [ "$md5_a" != "$md5_b" ]; then
            echo "$f changed."
        fi
    else
        echo "$f deleted."
    fi
done