#!/bin/bash
## SCARY's scheduler projects installer

URL=$1
if [ "$1" == "" ]; then
	echo "Usage: $0 URL_to_pack"
fi;

PACK_NAME=`echo $URL|awk -F FS="/" '{print $8}'`
echo "PACK NAME: $PACK_NAME"

