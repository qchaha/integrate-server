#!../flask/bin/python
from flask import request, abort, json
from pymongo import MongoClient
import pymysql
import datetime
import subprocess
import time


class Hosts:

    #静态变量，保存hostname和ip的对应信息在程序内存中
    host_table_inmem = []

    """初始化对象私有变量"""
    def __init__(self):
        self.mysql_srvip = "192.168.197.152"
        self.mysql_user = "root"
        self.mysql_pwd = "root123"
        self.mysql_db_name = "integrate"
        self.sql_fetch_all_ip = "select ip_address from host order by ip_address"
        self.sql_fetch_all_host = "select * from host order by ip_address"
        self.mongo_srvip = "192.168.197.152"
        self.mongo_port = 27017
        self.mongo_db_name = "integrate"
        self.wetty_config_file = "/root/wetty/tossh.sh"

    """获得gateone api认证"""
    @staticmethod
    def get_gateone_auth():
        import time, hmac, hashlib, json
        secret = b'NzYxNjMxNjFjNzFmNGQxOGE3NDJjYjlkNjk0MmEyN2NhO'
        authobj = {
            'api_key': "NmFlNzM4MmFjY2RjNDc5NDlmYTM0MTlmN2I4YjgwMDRhZ",
            'upn': "haha",
            'timestamp': str(int(time.time() * 1000)),
            'signature_method': 'HMAC-SHA1',
            'api_version': '1.0'
        }
        hash = hmac.new(secret, digestmod=hashlib.sha1)
        hash.update(authobj['api_key'].encode('utf-8') + authobj['upn'].encode('utf-8') + authobj['timestamp'].encode('utf-8'))
        authobj['signature'] = hash.hexdigest()
        valid_json_auth_object = json.dumps(authobj)
        return valid_json_auth_object

    """获得列表中的主机在线状态"""
    def check_host_alive(self):
        db = pymysql.connect( self.mysql_srvip, self.mysql_user, self.mysql_pwd, self.mysql_db_name )
        cursor = db.cursor()
        try:
            cursor.execute(self.sql_fetch_all_ip)
            results = cursor.fetchall()
            jresults = []
            for result in results:
                ret = subprocess.call("ping -c 1 %s" % result[0],shell=True,stdout=open('/dev/null','w'),stderr=subprocess.STDOUT)
                if ret == 0:
                    #print("%s | online" % result[0])
                    jresults.append("online")
                else:
                    #print("%s | offline" % result[0])
                    jresults.append("offline")
        except:
            print("error fetch ip from mysql!")
            abort(404)
        return jresults

    """从mysql中，获取所有主机的列表"""
    def find_all_host(self):
        db = pymysql.connect( self.mysql_srvip, self.mysql_user, self.mysql_pwd, self.mysql_db_name )
        cursor = db.cursor()
        try:
            cursor.execute(self.sql_fetch_all_host)
            results = cursor.fetchall()
            jresults = []
            for result in results:
                dresults = {}
                dresults['id'] = result[0]
                dresults['ip_address'] = result[1]
                dresults['hostname'] = result[2]
                dresults['admin_user'] = result[3]
                dresults['admin_password'] = result[4]
                dresults['os_type'] = result[5]
                dresults['os_detail'] = result[6]
                dresults['is_ssh'] = result[7]
                dresults['ssh_port'] = result[8]
                dresults['is_rdp'] = result[9]
                dresults['rdp_port'] = result[10]
                dresults['is_vnc'] = result[11]
                dresults['vnc_port'] = result[12]
                dresults['is_ftp'] = result[13]
                dresults['ftp_port'] = result[14]
                dresults['is_scp'] = result[15]
                dresults['scp_port'] = result[16]
                dresults['is_http'] = result[17]
                dresults['http_port'] = result[18]
                jresults.append(dresults)
                Hosts.host_table_inmem.append([result[1],result[2]])
                #print(Hosts.host_table_inmem)
            db.close()
        except:
            print("error fetch in host_data from mysql!")
            abort(404)
        return jresults
    
    """删除所选的主机"""   
    def delete_hosts(self):
        db = pymysql.connect( self.mysql_srvip, self.mysql_user, self.mysql_pwd, self.mysql_db_name )
        cursor = db.cursor()
        selected_ips = request.json['selected_ips']
        ips = ""
        op_result = ""
        for ip in selected_ips:
            #print(ip)
            ips = "\'" + ip + "\'," + ips
        ips = ips[:-1]
        sql = "delete from host where ip_address in(" + ips + ")"
        try:
            cursor.execute(sql)
            db.commit()
            db.close()
            op_result = "delete sucessful!"
        except:
            print("error fetch in delete_hosts from mysql!")
            op_result = "delete failure!"
        return  op_result
    
    """添加一台主机"""
    def add_hosts(self):
        if(request.json['add_host_ip'] == ""):
            abort(404)
        op_result = ""
        db = pymysql.connect( self.mysql_srvip, self.mysql_user, self.mysql_pwd, self.mysql_db_name )
        cursor = db.cursor()
        hostname = "default"
        #print(request.json['add_host_ip'],request.json['add_host_admin_user'],request.json['add_host_admin_password'],request.json['add_host_os'])
        sql = "insert into host values(null,'" \
              + request.json['add_host_ip'] + "','" \
              + hostname + "','" \
              + request.json['add_host_admin_user'] + "','" \
              + request.json['add_host_admin_password'] + "'," \
              + "'Linux','" + request.json['add_host_os'] + "',"\
              + "1,22,0,null,0,null,0,null,1,22,0,null)"
        print(sql)
        try:
            cursor.execute(sql)
            db.commit()
            db.close()
            op_result = "add sucessful!"
        except:
            print("error fetch in add_hosts from mysql!")
            op_result = "add failure!"
        return op_result

    """获取选中主机的实时信息，信息从队列中取"""
    def gehost_info( self, hostname ):
        #检查主机是否存活
        ip = ""
        for i in Hosts.host_table_inmem:
            if i[0] == hostname:
                ip = i[1]
                break
        isalive = self.ping(ip)
        #print(isalive)

        array = []
        #print(Hosts.host_table_inmem)
        if isalive == "offline":
            abort(404)
        else:
            try:
                conn = MongoClient(self.mongo_srvip, self.mongo_port)
                #连接到test数据库
                db = conn[self.mongo_db_name]
                #指向名为open的collection
                collection= db[hostname]
                #返回最新一条记录，-1表示降序，limit返回一条
                document = collection.find().sort([("date",-1)]).limit(1)
                for i in document:
                    break
                #获取X轴结束时间，一开始是想用本机服务器时间，但是万一被监控的机器与本机时间不同步，
                #那么可能会检查不到数据，因此现在改为获取被监控机最后一条监控信息的时间为X轴结束时间
                xaxis_end_time = datetime.datetime.strptime(i['date'], "%Y-%m-%d %H:%M:%S")
                xaxis_start_time = xaxis_end_time - datetime.timedelta(seconds=70)

                #只返回22条数据，因为前段echarts，X轴为21个点，返回条数过多时，时间显示会出现问题（X轴右边的数据比左边还要早）
                document = collection.find({"date": {"$gt": xaxis_start_time.strftime("%Y-%m-%d %H:%M:%S")}}).sort([("date", 1)])
                for i in document:
                    del i["_id"]
                    #print(json.dumps(i))
                    array.append(i)
            except:
                print("error on operating mongodb!")
                abort(404)
        return  array

    """ping命令"""
    def ping( self, ip ):
        ret = subprocess.call("ping -c 1 %s" % ip,shell=True,stdout=open('/dev/null','w'),stderr=subprocess.STDOUT)
        re = ''
        #返回值为0代表命令正常退出
        if ret == 0:
              #print("%s | online" % result[0])
              re = "online"
        else:
              #print("%s | offline" % result[0])
              re = "offline"
        return re

    """打开web tty"""
    def open_wetty( self ):
        cmd = "sed -i -e '1cssh root@" + request.json['ip'] + "' " + self.wetty_config_file
        ret = subprocess.call(cmd, shell=True,stdout=open('/dev/null','w'),stderr=subprocess.STDOUT)
        re = ''
        #返回值为0代表命令正常退出
        if ret == 0:
            re = "edit wetty config file success!"
        else:
            re = "edit wetty config file error!"
        return re


"""
def mping(i,q):
    n = 10
    while n > 0:
        n -= 1
        ip = q.get()
        ret = subprocess.call("ping -c 1 %s" % ip,shell=True,stdout=open('/dev/null','w'),stderr=subprocess.STDOUT)
        if ret == 0:
            #print("%s | Ok" % ip)
            re = "alive"
        else:
            #print("%s | No" % ip)
            re = "noalive"
        q.task_done()
        return re

def check_host_ping():
        num_threads = 3
        queue = Queue()
        ips = ["192.168.197.151","192.168.197.152","192.168.197.153"]
        for i in range(num_threads):
            worker = Thread(target=mping,args=(i,queue))
            worker.setDaemon(True)
            worker.start()
        for ip in ips:
            queue.put(ip)
        #queue.join()
"""
