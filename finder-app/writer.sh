#!/bin/sh

# Author : Mohsin Sardar


#echo Script name: $0
#echo $# arguments 
if [ $# -ne 2 ]; then
#    echo "Illegal Arguments: Follow Below Format\n./writer.sh <Write File Name> <Write String>"
    exit 1
fi

WRITEFILE="$1"
WRITESTR="$2"
FILEDIR=$( dirname "$WRITEFILE" )

if test -f "$WRITEFILE"; then
    echo "$WRITESTR">>$WRITEFILE

    #echo "The number of files are $X and the number of matching lines are $Y:"
else
#    echo "$WRITEFILE Does not Exists: Enter Valid Write File"
    mkdir -p $FILEDIR 2>/dev/null
    if [ $? -ne 0 ]; then
	    exit 1
    fi

    touch $WRITEFILE 2>/dev/null
    if [ $? -ne 0 ]; then
	    exit 1
    fi
    echo "$WRITESTR">>$WRITEFILE
fi


