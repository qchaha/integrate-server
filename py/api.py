#!../flask/bin/python
from flask import Flask, jsonify, make_response, request, abort, render_template, json
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
import requests
from Hosts import Hosts
from ScriptManager import Scripts

# 静态文件的放置路径，可根据实际情况设置，这里设置为默认路径：'./static/'
app = Flask(__name__,static_url_path='', root_path='/root/py/integrate-server/')


@app.route('/api/get_gateone_auth',methods=['GET'])
def get_gateone_auth():
    valid_json_auth_object = Hosts.get_gateone_auth()
    return valid_json_auth_object

@app.route('/api/check_host_alive_v1.0',methods=['GET'])
def check_host_alive():
    ins = Hosts()
    jresults = ins.check_host_alive()
    return jsonify({'host_alive_info': jresults})

@app.route('/api/find_all_host_v1.0',methods=['GET'])
def find_all_host():
    ins = Hosts()
    jresults = ins.find_all_host()
    return jsonify({'host_info': jresults})

@app.route('/api/delete_hosts_v1.0', methods=['POST'])
def delete_hosts():
    ins = Hosts()
    op_result = ins.delete_hosts()
    return  jsonify({"op_result": op_result})

@app.route('/api/add_hosts_v1.0', methods=['POST'])
def add_hosts():
    ins = Hosts()
    op_result = ins.add_hosts()
    return jsonify({"op_result": op_result})

@app.route('/kafka/get_host_info_v1.1/<string:hostname>', methods=['GET'])
def get_host_info(hostname):
    ins = Hosts()
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
    ins = Hosts()
    rt_msg = ins.login_auth( request.json['username'], request.json['encrypt_password'] )
    if rt_msg == 1:
        rt_token = Hosts.jwt_visit_token
    elif rt_msg == -1:
        rt_token = "invalid token!"
    return jsonify({ "rt_token": rt_token })

#访问页面前认证
@app.route('/api/isauth_v1.0' , methods = ['POST'])
def test():
    if request.json['visit_token'] == Hosts.jwt_visit_token:
        s = Serializer( secret_key = "verify_complex", salt = "auth_salt_verylong" )
        try:
            data = s.loads(Hosts.jwt_visit_token)
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
        rt_msg = "no because visit is :" + Hosts.jwt_visit_token
    return jsonify({ "rt_msg": rt_msg })


@app.route('/api/open_wetty_v1.0', methods = ['POST'])
def open_wetty():
    ins = Hosts()
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


@app.route('/api/fetch_all_scripts_v1.0', methods = ['GET'])
def fetch_all_scripts():
    ins = Scripts()
    re = ins.fetch_all_script_info()
    return jsonify({"script": re})

@app.route('/api/fetch_script_content_v1.0', methods = ['POST'])
def fetch_script_content():
    script_name = request.json["script_name"]
    ins = Scripts()
    re = ins.fetch_script_content(script_name)
    return jsonify({"script_content": re})

@app.route('/api/new_or_import_script_v1.0', methods = ['POST'])
def import_script():
    script_content = request.json['script_content']
    script_name = request.json['script_name']
    script_tags = request.json['script_tags']
    script_descript = request.json['script_description']
    ins = Scripts()
    re = ins.import_script( script_content, script_name, script_tags, script_descript )
    return jsonify({"import_script": re})

@app.route('/api/delete_script_v1.0', methods = ['POST'])
def delete_script():
    select_script_names = request.json['select_script_names']
    ins = Scripts()
    re = ins.delete_script( select_script_names )
    return jsonify({"delete_script_result": re})

#处理select2的脚本标签
@app.route('/api/fetch_all_script_tags_v1.0', methods = ['GET'])
def fetch_all_script_tags():
    ins = Scripts()
    re = ins.fetch_all_script_tags()
    return jsonify({"script_tags": re})

#查看新建、导入的脚本名是否已经存在
@app.route('/api/shell_syntax_check_v1.0', methods = ['POST'])
def shell_syntax_check():
    script_content = request.json['script_content']
    ins = Scripts()
    re = ins.shell_syntax_check(script_content)
    return jsonify({"shell_check_result": re})




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
