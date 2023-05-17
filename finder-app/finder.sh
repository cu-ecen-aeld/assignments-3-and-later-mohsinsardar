#!/bin/sh

# Author : Mohsin Sardar


#echo Script name: $0
#echo $# arguments 
if [ $# -ne 2 ]; then
#    echo "Illegal Arguments: Follow Below Format\n./finder.sh <Directory Name> <Search Key Word>"
    exit 1
fi

FILEDIR="$1"
SEARCHSTR="$2"

if test -d "$FILEDIR"; then
    X=$(find "$FILEDIR/". -type f | wc -l)

    Y=$(grep -l -r "$SEARCHSTR" "$FILEDIR"* | wc -l)
    echo "The number of files are $X and the number of matching lines are $Y:"
else
#    echo "$FILEDIR Does not Exists: Enter Valid Directory"
    exit 1
fi


