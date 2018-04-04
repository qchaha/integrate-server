 1. master

[mysqld]
log-bin = /var/lib/mysql-binlog/binlog
server-id = 1

mysql>create user 'rong'@'%' identified by 'root123';
mysql>grant replication slave on *.* to 'rong'@'%';


2.slave

[mysqld]
server-id = 2
relay-log = /var/lib/mysql/relaylog


mysql>CHANGE MASTER TO MASTER_HOST='172.17.0.2', MASTER_USER='rong', MASTER_PASSWORD='root123', MASTER_LOG_FILE='binlog.000001',MASTER_LOG_POS=0;

mysql>start slave






mysqldump -uroot -proot --all-databases >/tmp/all.sql
mysqldump -uroot -proot --databases db1 db2 >/tmp/user.sql
mysqldump -uroot -proot --databases db1 --tables a1 a2  >/tmp/db1.sql



mysql>source all.sql