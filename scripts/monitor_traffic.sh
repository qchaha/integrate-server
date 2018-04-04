#!/bin/sh

function Usage 
{
	echo "Usage: $0 interface frequence"
	echo "e.g: $0 eth0 1"
	exit 1
}

if [ $# -lt 2 ]; then
	Usage
fi


echo -e "##########  Network Traffic Monitor v1.0  ###############\n
						     \n
###########             by me 2011 12 4  ################\n"
while true
do
Old_in=$(cat /proc/net/dev | grep $1 | awk '{ print $2 }')
Old_out=$(cat /proc/net/dev | grep $1 | awk '{ print $10 }')
sleep $2
New_in=$(cat /proc/net/dev | grep $1 | awk '{ print $2 }')
New_out=$(cat /proc/net/dev | grep $1 | awk '{ print $10 }')
In=$(((New_in-Old_in)/$2))
Out=$(((New_out-Old_out)/$2))
# display by byte/s
#echo "#      IN: $In bytes		OUT: $Out bytes		#"
# display by KB/s
echo "#      IN: $((In/1024)).$((In%1024)) KB	             OUT: $((Out/1024)).$((Out%1024)) KB	#"
done 

exit 0
