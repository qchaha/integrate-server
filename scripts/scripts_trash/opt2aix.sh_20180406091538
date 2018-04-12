#!/usr/bin/ksh
############################################
# GZWEISS GaryWei for CJIS AIX  20140923   #
#                                          #
# create table opt_table (                 #
#    opt_datetime          date,           #
#    instance_name         varchar2(30),   #
#    db_total_sessions     number,         #
#    db_active_sessions    number,         #
#    db_total_sga          number,         #
#    db_total_pga          number,         #
#    cpu_user_percentage   number,         #
#    cpu_system_percentage number,         #
#    cpu_idle_percentage   number,         #
#    cpu_wait_percentage   number,         #
#    io_read_kb            number,         #
#    io_write_kb           number);        #
############################################

DB_USER_PASSWORD=' / AS SYSDBA'
VMSTAT_TEMP_FILE='vmstat.log'
IOSTAT_TEMP_FILE='iostat.log'
IO_DISK_LIST="hdisk2 hdisk3 hdisk4"

CPU_USER_PERCENTAGE=0
CPU_SYSTEM_PERCENTAGE=0
CPU_IDLE_PERCENTAGE=0
CPU_WAIT_PERCENTAGE=0

vmstat 1 2 1>$VMSTAT_TEMP_FILE
iostat 1 2 1>$IOSTAT_TEMP_FILE

VMSTAT_RESULT=`tail -1 $VMSTAT_TEMP_FILE`

CPU_USER_PERCENTAGE=`echo $VMSTAT_RESULT|awk '{print $14}'`
CPU_SYSTEM_PERCENTAGE=`echo $VMSTAT_RESULT|awk '{print $15}'`
CPU_IDLE_PERCENTAGE=`echo $VMSTAT_RESULT|awk '{print $16}'`
CPU_WAIT_PERCENTAGE=`echo $VMSTAT_RESULT|awk '{print $17}'`

IO_READ_KB=0
IO_WRITE_KB=0
IOSTAT_LINE_COUNT=0
IOSTAT_LINE_NUMBER=`cat $IOSTAT_TEMP_FILE|wc -l`
let "IOSTAT_LINE_NUMBER = $IOSTAT_LINE_NUMBER / 2 -6 "
tail -$IOSTAT_LINE_NUMBER $IOSTAT_TEMP_FILE|while read IOSTAT_LINE
do
        IOSTAT_DISK_NAME=`echo $IOSTAT_LINE|awk '{print $1}'`
        if [ -n "`echo $IO_DISK_LIST|grep $IOSTAT_DISK_NAME`" ] ; then
        	let "IOSTAT_LINE_COUNT = $IOSTAT_LINE_COUNT + 1"
		let "IO_READ_KB = $IO_READ_KB + `echo $IOSTAT_LINE|awk '{print $5}'`" 
		let "IO_WRITE_KB = $IO_WRITE_KB + `echo $IOSTAT_LINE|awk '{print $6}'`" 
        fi
done

sqlplus -S $DB_USER_PASSWORD <<EOF
set echo     off
set feedback off
DECLARE
  v_instance_name      varchar2(30);
  v_db_total_sessions  number;
  v_db_active_sessions number;
  v_db_total_sga       number;
  v_db_total_pga       number;
BEGIN
  select instance_name       into v_instance_name from v\$instance;  
  select count(1)            into v_db_total_sessions from v\$session;
  select count(1)            into v_db_active_sessions from v\$session where status='ACTIVE';
  select sum(value)          into v_db_total_sga from v\$sga;
  select sum(pga_alloc_mem)  into v_db_total_pga from v\$process;
  insert into opt_table ( 
     opt_datetime,
     instance_name,
     db_total_sessions,
     db_active_sessions,
     db_total_sga,db_total_pga,
     cpu_user_percentage,
     cpu_system_percentage,
     cpu_idle_percentage,
     cpu_wait_percentage,
     io_read_kb,
     io_write_kb)
  values (
     SYSDATE,
     v_instance_name,
     v_db_total_sessions,
     v_db_active_sessions,
     v_db_total_sga,
     v_db_total_pga,
     $CPU_USER_PERCENTAGE,
     $CPU_SYSTEM_PERCENTAGE,
     $CPU_IDLE_PERCENTAGE,
     $CPU_WAIT_PERCENTAGE,
     $IO_READ_KB,
     $IO_WRITE_KB);
     commit;
END;
/
EOF
