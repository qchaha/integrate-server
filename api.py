#!flask/bin/python
from flask import Flask, jsonify, make_response, request, abort, render_template, json
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from pymongo import MongoClient
import pymysql
import datetime
import subprocess
import time
import requests

# 静态文件的放置路径，可根据实际情况设置，这里设置为默认路径：'./static/'
app = Flask(__name__, static_url_path='')


class Monitor:

    #静态变量，保存hostname和ip的对应信息在程序内存中
    host_table_inmem = []
    #静态变量，保存jwt,类内访问时需要Monitor.jwt_token
    jwt_visit_token = ""

    """初始化对象私有变量"""
    def __init__(self):
        self.mysql_srvip = "192.168.197.152"
        self.mysql_user = "root"
        self.mysql_pwd = "root123"
        self.mysql_db_name = "test"
        self.sql_fetch_all_ip = "select ip_address from t_host order by ip_address"
        self.sql_fetch_all_host = "select * from t_host order by ip_address"
        self.mongo_srvip = "192.168.197.152"
        self.mongo_port = 27017
        self.mongo_db_name = "test"
        self.jwt_secret_key = "verify_complex"
        self.jwt_salt_key = "auth_salt_verylong"
        self.jwt_visit_expire_time = 3600
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
                Monitor.host_table_inmem.append([result[1],result[2]])
                #print(Monitor.host_table_inmem)
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
        sql = "delete from t_host where ip_address in(" + ips + ")"
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
        sql = "insert into t_host values(null,'" + request.json['add_host_ip'] + "','" + hostname + "','" + request.json['add_host_admin_user'] + "','" + request.json['add_host_admin_password'] + "','" + request.json['add_host_os'] + "','Mysql')"
        #print(sql)
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
    def get_host_info( self, hostname ):
        #检查主机是否存活
        ip = ""
        for i in Monitor.host_table_inmem:
            if i[0] == hostname:
                ip = i[1]
                break
        isalive = self.ping(ip)
        #print(isalive)

        array = []
        #print(Monitor.host_table_inmem)
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

    """JWT 生成token"""
    def generate_token( self ):
        """
        JWT（json web token）一共包含三个内容：
        1.头部；
        2.payload(s.dumps()的内容)；
        3.签名（secret_key,salt_key）
        Serializer()函数自动生成头部和签名，只需要payload写进入
        """
        s = Serializer( secret_key = self.jwt_secret_key, salt = self.jwt_salt_key, expires_in = self.jwt_visit_expire_time )
        timestamp = time.time()
        Monitor.jwt_visit_token = s.dumps( { "admin_user" : "admin" , "admin_password" : "admin123", "iat": timestamp } ).decode("utf-8")            
        rt_token = Monitor.jwt_visit_token
        return rt_token

    """JWT 校验token"""
    def verify_token( self ):
        s = Serializer( secret_key = self.jwt_secret_key, salt = self.jwt_salt_key )
        #print(request.json['token'])
        #print(Monitor.jwt_token)
        try:
            data = s.loads(Monitor.jwt_token)
        #token expired
        except SignatureExpired:
            return "token expired!"
        #invalid token
        except BadSignature:
            return "invalid token! signature may be modified!"
        except:
            return "token require error!"
        return data

    """认证身份，返回1则代表成功，进行跳转；返回-1则表示失败，重新输入"""
    def login_auth( self, r_admin_user, r_encrypt_password ):
        db = pymysql.connect( self.mysql_srvip, self.mysql_user, self.mysql_pwd, self.mysql_db_name )
        cursor = db.cursor()
        try:
            cursor.execute("select admin_user, admin_password from t_host where admin_user = 'root' and ip_address='192.168.197.152'")
            results = cursor.fetchall()
            for result in results:
                admin_user = result[0]
                encrypt_password = result[1]
            db.close()
        except:
            print("error fetch in admin password from mysql!")
            abort(404)

        if r_encrypt_password == encrypt_password and admin_user == r_admin_user:
            Monitor.jwt_visit_token = self.generate_token()
            rt_msg = 1
        else:
            Monitor.jwt_visit_token = "login auth failure!"
            rt_msg = -1
        #print("visit_token: " + Monitor.jwt_visit_token)
        return rt_msg

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

@app.route('/api/get_gateone_auth',methods=['GET'])
def get_gateone_auth():
    valid_json_auth_object = Monitor.get_gateone_auth()
    return valid_json_auth_object

@app.route('/api/check_host_alive_v1.0',methods=['GET'])
def check_host_alive():
    ins = Monitor()
    jresults = ins.check_host_alive()
    return jsonify({'host_alive_info': jresults})

@app.route('/api/find_all_host_v1.0',methods=['GET'])
def find_all_host():
    ins = Monitor()
    jresults = ins.find_all_host()
    return jsonify({'host_info': jresults})

@app.route('/api/delete_hosts_v1.0', methods=['POST'])
def delete_hosts():
    ins = Monitor()
    op_result = ins.delete_hosts()
    return  jsonify({"op_result": op_result})

@app.route('/api/add_hosts_v1.0', methods=['POST'])
def add_hosts():
    ins = Monitor()
    op_result = ins.add_hosts()
    return jsonify({"op_result": op_result})

@app.route('/kafka/get_host_info_v1.1/<string:hostname>', methods=['GET'])
def get_host_info(hostname):
    ins = Monitor()
    array = ins.get_host_info(hostname)
    return jsonify({'host_data': array})

#设置根路由
@app.route('/')
def root():
    return app.send_static_file('index.html')

#404
@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Pages Not found'}), 404)

#登录认证
@app.route('/api/login_auth_v1.0', methods=['POST'])
def login_auth():
    ins = Monitor()
    rt_msg = ins.login_auth( request.json['username'], request.json['encrypt_password'] )
    if rt_msg == 1:
        rt_token = Monitor.jwt_visit_token
    elif rt_msg == -1:
        rt_token = "invalid token!"
    return jsonify({ "rt_token": rt_token })

#访问页面前认证
@app.route('/api/test' , methods = ['POST'])
def test():
    print("re:  " + request.json['visit_token'])
    print("to:  " + Monitor.jwt_visit_token)
    if request.json['visit_token'] == Monitor.jwt_visit_token:
        s = Serializer( secret_key = "verify_complex", salt = "auth_salt_verylong" )
        #print(request.json['token'])
        #print(Monitor.jwt_token)
        try:
            data = s.loads(Monitor.jwt_visit_token)
            print(data)
            rt_msg = "auth ok!"
        #token expired
        except SignatureExpired:
            rt_msg = "token expired!"
        #invalid token
        except BadSignature:
            rt_msg = "invalid token! signature may be modified!"
        except:
            rt_msg = "token require error!"
    else:
        rt_msg = "no because visit is :" + Monitor.jwt_visit_token
    return jsonify({ "rt_msg": rt_msg })


@app.route('/api/open_wetty_v1.0', methods = ['POST'])
def open_wetty():
    ins = Monitor()
    re = ins.open_wetty()
    return jsonify({"can_open_wetty": re})




@app.route('/api/remote_desktop_v1.0', methods = ['POST'])
def show_remote_desktop():
    protocol = request.json['protocol']
    ip = request.json['ip']
    if protocol == "rdp":
        user = "administrator"
        password = "1qaz@WSX"
        port = 3389
    elif protocol == "vnc":
        user = ""
        password = "admin"
        port = 15900
    payload = {'protocol': protocol, 'ip': ip, 'user': user, 'password': password, 'port': port}
    r = requests.post("http://192.168.197.152:5001/api/guac_interface_v1.0", data = payload)
    return "dd"



if __name__ == '__main__':
    app.run(host='192.168.197.152',port=5000,debug=True,threaded=True)




















#模拟json数据
tasks = [
{
'id': 1,'title': u'Buy groceries','description': u'Milk, Cheese, Pizza, Fruit, Tylenol','done': False
}
]


#GET方法api
@app.route('/todo/api/tasks', methods=['GET'])
def getTasks():
    return jsonify({'tasks': tasks})

#获取指定id的task
@app.route('/todo/api/tasks/<int:task_id>',methods=['GET'])
def get_task(task_id):
    if task_id > len(tasks):
        abort(404)
    for task in tasks:
        if task['id'] == task_id:
            re = task;
    return jsonify({'task': re})

#POST方法API，添加数据项
@app.route('/todo/api/addTask', methods=['POST'])
def add_task():
    if request.json['title'] == "":
        abort(400)
    task = {
    'id' : tasks[-1]['id'] + 1,
    'title': request.json['title'],
    'description' : request.json.get('description', ""),
    'done' : False
    }
    tasks.append(task)
    return jsonify({'tasks': tasks}), 201

#POST方法API，删除数据项
@app.route('/todo/api/deleteTask', methods=['POST'])
def delete_task():
    task_id = request.json['id']
    for task in tasks:
        if task['id'] == task_id:
            tasks.remove(task)
    return jsonify({'tasks': tasks}), 201
