################################
#  Database  auto check script #
#  2017-06-15                  #
#  v1.0                        #
#  By Gary Wei                 #
#  Gz WeiSS                    #
################################

#!/bin/bash

echo $LOCALIP $ORACLE_SID $CHECKDATETIME
echo =====================================

echo
echo [OS filesystem space used]
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>"
echo
df -m

echo
echo [ASM Disk group space used]
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>"
$ORACLE_HOME/bin/sqlplus -S " / as sysdba " <<EOF
set line 120
set feedback off
col group_number format 99999
col name		format  a10
col total_mb		format  99999999
col free_mb		format  99999999
col usable_file_mb	format  99999999
col "USED%" 		format a10
col "FREE%" 		format a10
col critical 		format a10
col offline_disks format 999
select group_number,offline_disks,name,total_mb,free_mb,usable_file_mb,round((total_mb-free_mb)/total_mb*100)||'%' "USED%",round((free_mb)/total_mb*100)||'%' "FREE%",
	 (case when (usable_file_mb/total_mb) < 0.1 then '*' when (usable_file_mb/total_mb) < 0.05 then '**' when  (usable_file_mb/total_mb) <0.01 or offline_disks>0 then '***' else null end ) critical
	from v\$asm_diskgroup;
EOF

echo 
echo [Instance Status]
echo ">>>>>>>>>>>>>>>>>"
$ORACLE_HOME/bin/sqlplus -S " / as sysdba "<<EOF
set line 120
set feedback off
col inst_id 		format a10
col instancd_name 	format a30
col host_name	 	format a30
col start_time 		format a30
col status 		format a20
col critical		format a15
select ' '||to_char(inst_id) inst_id,instance_name,host_name,to_char(startup_time,'yyyy-mm-dd hh24:mi:ss') startup_time,status,decode(status,'OPEN',null,'*') critical
   	from gv\$instance where inst_id<>SYS_CONTEXT('USERENV','INSTANCE') 
union 
select '>'||sys_context('USERENV','INSTANCE') Inst_id,instance_name,host_name,to_char(startup_time,'yyyy-mm-dd hh24:mi:ss') startup_time,status ,decode(status,'OPEN',null,'*') critical
	from v\$instance 
order by instance_name ;
EOF


echo
echo [Tablespace space used]
echo ">>>>>>>>>>>>>>>>>>>>>>"
$ORACLE_HOME/bin/sqlplus -S " / as sysdba " <<EOF
set line 200
set pagesize 200
set feedback off
col tablespace_name 	format a30
col total_mb 		format 9999999
col free_mb 		format 9999999
col "USED%" 		format a10
col "FREE%"		format a10
col critical 		format a10
select a.tablespace_name,round(a.m) total_mb,round(b.m) free_mb,round((a.m-b.m)/a.m*100)||'%' "USED%",round((b.m)/a.m*100)||'%' "FREE%" ,
 	(case when (b.m/a.m) < 0.1 then '*' when (b.m/a.m) < 0.05 then '**' when  (b.m/a.m) <0.01 then '***' else null end ) critical
	from
		(select tablespace_name,sum(bytes)/1024/1024 m from dba_data_files group by tablespace_name) a,
		(select tablespace_name,sum(bytes)/1024/1024 m from dba_free_space group by tablespace_name) b
		where a.tablespace_name=b.tablespace_name(+);
EOF


echo
echo [RMAN backup]
echo ">>>>>>>>>>>>>"
$ORACLE_HOME/bin/sqlplus -S " / as sysdba " <<EOF
set line 150
set pagesize 1000
set feedback off
col start_time 		format a25
col end_time 		format a25
col operation		format a10
col input_mb		format 9999999
col output_mb 		format 9999999
col mbytes_processed 	format 9999999
col object_type		format a12
col status		format a12
col critical		format a12
select to_char(start_time,'yyyy-mm-dd hh24:mi:ss') start_time,to_char(end_time,'yyyy-mm-dd hh24:mi:ss') end_time,
	operation,round(input_bytes/1024/1024) input_mb,round(output_bytes/1024/1024) output_mb,mbytes_processed processed_mb,object_type,status ,
        decode(status,'COMPLETED',null,'*') critical
	from v\$rman_status where start_time>=(select trunc(max(start_time)-2) from v\$rman_status) 
	order by recid;
EOF

echo
echo [DataGuard Standby managed processes]
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
$ORACLE_HOME/bin/sqlplus -S "/ as sysdba" <<EOF
set line 120
set feedback off
col inst_id 	format 999999
col sequence# 	format 999999999
col process	format a30
col status	format a20
select inst_id,process,sequence#,status from gv\$managed_standby where process in ('RFS','MRP0') and sequence#>0 order by 1;
EOF


echo
echo [DataGuard DGMGRL Status]
echo ">>>>>>>>>>>>>>>>>>>>>>>>"
$ORACLE_HOME/bin/dgmgrl / "show configuration"|tail -10


echo
echo [Instance alert log errors or warings in the last 1000 rows]
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
tail -1000 $ORACLE_ALERTLOG|grep -n "ORA-"

echo
echo [Finish]
echo ========


