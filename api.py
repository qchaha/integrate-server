#!flask/bin/python
from flask import Flask, jsonify, make_response, request, abort, render_template, json
from pymongo import MongoClient
import pymysql
import datetime
import subprocess

# 静态文件的放置路径，可根据实际情况设置，这里设置为默认路径：'./static/'
app = Flask(__name__, static_url_path='')

#全局变量，保存hostname和ip的对应信息在程序内存中
global_host_table_inmem = []


def ping(ip):
    ret = subprocess.call("ping -c 1 %s" % ip,shell=True,stdout=open('/dev/null','w'),stderr=subprocess.STDOUT)
    re = ''
    if ret == 0:
          #print("%s | online" % result[0])
          re = "online"
    else:
          #print("%s | offline" % result[0])
          re = "offline"
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
    import time, hmac, hashlib, json
    secret = b'ZDhiMjZiMGU0Y2YxNGJjOTkxZmE3ZjMwZTZiNDQwOWRhZ'
    authobj = {
    'api_key': "ZjhlNDljMTNmNzlmNDYxYjhlOGJlY2I4MDVmOWJiN2U2M",
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

@app.route('/api/check_host_alive_v1.0',methods=['GET'])
def check_host_alive():
    db = pymysql.connect("192.168.197.152", "root", "root123", "test")
    cursor = db.cursor()
    sql = "select ip_address from t_host order by ip_address"
    try:
        cursor.execute(sql)
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
    return jsonify({'host_alive_info': jresults})


@app.route('/api/find_all_host_v1.0',methods=['GET'])
def find_all_host():
    db = pymysql.connect("192.168.197.152", "root", "root123", "test")
    cursor = db.cursor()
    sql = "select id,hostname,ip_address,os_type,app_type from t_host order by ip_address"
    try:
        cursor.execute(sql)
        results = cursor.fetchall()
        jresults = []
        for result in results:
            dresults = {}
            dresults['id'] = result[0]
            dresults['hostname'] = result[1]
            dresults['ip_address'] = result[2]
            dresults['os_type'] = result[3]
            dresults['app_type'] = result[4]
            jresults.append(dresults)
            global_host_table_inmem.append([result[1],result[2]])
            #print(dresults['ip_address'])
        db.close()
    except:
        print("error fetch in host_data from mysql!")
        abort(404)
    return jsonify({'host_info': jresults})


@app.route('/api/delete_hosts_v1.0', methods=['POST'])
def delete_hosts():
    db = pymysql.connect( "192.168.197.152", "root", "root123", "test" )
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
    return  jsonify({"op_result": op_result})

@app.route('/api/add_hosts_v1.0', methods=['POST'])
def add_hosts():
    if(request.json['add_host_ip'] == ""):
        abort(404)
    op_result = ""
    db = pymysql.connect( "192.168.197.152", "root", "root123", "test" )
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
    return jsonify({"op_result": op_result})


@app.route('/kafka/get_host_info_v1.1/<string:hostname>', methods=['GET'])
def get_host_info(hostname):
    #检查主机是否存活
    ip = ""
    for i in global_host_table_inmem:
        if i[0] == hostname:
            ip = i[1]
            break
    isalive = ping(ip)

    array = []
    #print(isalive)
    if isalive == "offline":
        abort(404)
    else:
        try:
            conn = MongoClient('192.168.197.152', 27017)
            #连接到test数据库
            db = conn['test']
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

    return jsonify({'host_data': array})



@app.route('/kafka/get_host_info', methods=['GET'])
def test():
    conn = MongoClient('192.168.197.152', 27017)
    db = conn['test']
    my_set = db['open']
    r = my_set.find({"date": {"$gt": "2018-02-07 11:45:00"}})
    for i in r:
        del i["_id"]
        #print(json.dumps(i))

    return jsonify({'host_data': i})

#设置根路由
@app.route('/')
def root():
    return app.send_static_file('index.html')


#404
@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Pages Not found'}), 404)























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




if __name__ == '__main__':
    app.run(host='192.168.197.152',port=5000,debug=True)
