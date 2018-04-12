#!/bin/bash

function Usage
{
	echo -e "\nUsage: $0 packet/s\n"
	echo -e "e.g: $0 100  ( about 100*1.5kb=150kb/s )\n"	
	exit 64
}

if [ $# -ne 1 ]; then
	Usage
fi

if [ `whoami` != "root" ];then
	echo -e "\nyou must exec the script under root\n"
	exit 65
fi

if [ -f /tmp/iptables.tmp ]; then

	rm /tmp/iptables.tmp

	else
		> /tmp/iptables.tmp
		chmod +x /tmp/iptables.tmp
fi


#---------get current values and save to /tmp/iptables.tmp----------------------------------------------------------------------------------------
line_count=$(iptables -S | wc -l)
key_to_control_while=1
while [ $key_to_control_while -le $line_count ]
do
#sleep 1 
temp_string=$(iptables -S | sed -n "${key_to_control_while}p")
#echo $temp_string
echo $temp_string | grep "\-m limit \-\-limit" > /dev/null

if [ $? == 0 ];then
	temp_string=$(iptables -S | sed -n "${key_to_control_while}p" | sed "s/\-m limit \-\-limit [0-9]*\/s/\-m limit \-\-limit $1\/s/" | sed "s/^/iptables /g")
	else
		temp_string=$(iptables -S | sed -n "${key_to_control_while}p" | sed "s/-j ACCEPT/\-m limit \-\-limit $1\/s -j ACCEPT/g" | sed "s/^/iptables /g")
fi
echo $temp_string >> /tmp/iptables.tmp
key_to_control_while=$(echo "${key_to_control_while} + 1" | bc)
done
#-------------------------------------------------------------------------------------------------------------------------------------------------
#process
iptables -F 
sh /tmp/iptables.tmp

if [ $? != 0 ];then

	echo -e "\nfailure to exec the script!\n"
	rm /tmp/iptables.tmp

	else
		rm /tmp/iptables.tmp
		SPEED=$(echo " $1 * 1.5 " | bc)
		echo -e "\nOK! the speed was restricted in ${SPEED}kb/s\n"	
fi

exit 0
