#/bin/bash

usage() {
    echo "input file name which will be read for testing."
}
if [ $# -eq 0 ]; then
    usage
    exit
fi

if [ -e $1 ]; then
    echo "Next will test the file: $1"
else
    echo "Can't find this file: $1"
    exit
fi


echo -e "\n\n solution 1: use 'redirect input'"
while read rows
do
    echo "Line: $rows"
done < $1


echo -e "\n\n Solution2: use cat and pipe"
cat $1 | while read rows
do
    echo "Line: $rows"
done

echo -e "\n\n Solution3: use awk to parse the line string"
cat $1 | awk '{print "Line contents are: "$0}'
