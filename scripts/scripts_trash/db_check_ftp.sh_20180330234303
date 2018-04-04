################################
#  Database  auto check script #
#  2017-06-15                  #
#  v1.0                        #
#  By Gary Wei                 #
#  Gz WeiSS                    #
################################

#!/bin/bash
export LOCALIP=192.168.150.11
export FTPSERVERIP=192.168.160.88
export FTPUSERNAME=oracle
export FTPUSEPASSWORD=oracle
export FTPDIR=/weiss
export SCRIPTDIR=/home/oracle/weiss/db_check
export CHECKDATE=`date "+%Y-%m-%d"`
export CHECKDATETIME=`date "+%Y-%m-%d_%H%M%S"`
export ORACLE_SID=vipcard1
export ORACLE_HOME=/u01/oracle/product/dbhome_2
export ORACLE_ALERTLOG=/u01/oracle/diag/rdbms/vipcard/vipcard1/trace/alert_vipcard1.log
export DBCHECKLOGFILE=${ORACLE_SID}_${LOCALIP}_${CHECKDATETIME}.log

cd $SCRIPTDIR

/bin/sh db_check.sh>$DBCHECKLOGFILE

ftp -n $FTPSERVERIP <<EOF
user $FTPUSERNAME $FTPUSEPASSWORD
	prom
	bin
	mkdir 	$FTPDIR/$CHECKDATE
	cd 	$FTPDIR/$CHECKDATE
	put 	$DBCHECKLOGFILE 
EOF
