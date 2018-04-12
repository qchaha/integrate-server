#!../flask/bin/python
from flask import Flask, jsonify, make_response, request, abort, render_template, json
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
import requests
from Hosts import Hosts
from Jwt import Jwt
from Processes import Processes
from ScriptManager import Scripts

from functools import wraps

# 静态文件的放置路径，可根据实际情况设置，这里设置为默认路径：'./static/'
app = Flask(__name__,static_url_path='', root_path='/root/py/integrate-server/')

"""-------------------------------------------------------------------------
访问任何资源前，身份认证
-------------------------------------------------------------------------"""

#检验jwt token的装饰器,放到所有引用前
def jwt_token_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if request.json['visit_token'] is not None and Jwt.jwt_visit_token != []:
            for token in Jwt.jwt_visit_token:
                if token == request.json['visit_token']:
                    s = Serializer( secret_key = "verify_complex", salt = "auth_salt_verylong" )
                    try:
                        data = s.loads(token)
                        """------------------------------------------------------------------------
                            这里预留鉴权代码, 从data即可取出当前用户的role或者相关信息
                        
                            print(data):
                                {'role': 'admin', 'user': 'root', 'iat': 1523408863.878809}
                        
                        ------------------------------------------------------------------------"""
                        get_token_msg = "auth ok!"
                        kwargs['get_token_msg'] = get_token_msg
                    #token expired
                    except SignatureExpired:
                        get_token_msg = "token expired!"
                        kwargs['get_token_msg'] = get_token_msg
                    #invalid token
                    except BadSignature:
                        get_token_msg = "invalid token! signature may be modified!"
                        kwargs['get_token_msg'] = get_token_msg
                    except:
                        get_token_msg = "token require error!"
                        kwargs['get_token_msg'] = get_token_msg
                    break
                else:
                    get_token_msg = "invalid token! signature may be modified!"
                    kwargs['get_token_msg'] = get_token_msg   
        else:
            get_token_msg = "can not find token!"
            kwargs['get_token_msg'] = get_token_msg
        return func(*args, **kwargs)
    return wrapper

"""-------------------------------------------------------------------------
Hosts页面
-------------------------------------------------------------------------"""

@app.route('/api/check_host_alive_v1.0',methods=['POST'])
@jwt_token_required
def check_host_alive(get_token_msg):
    if get_token_msg == "auth ok!":
        ins = Hosts()
        jresults = ins.check_host_alive()
    else:
        jresults = get_token_msg
    return jsonify({'host_alive_info': jresults})

@app.route('/api/find_all_host_v1.0',methods=['POST'])
@jwt_token_required
def find_all_host(get_token_msg):
    if get_token_msg == "auth ok!":
        ins = Hosts()
        jresults = ins.find_all_host()
    else:
        jresults = get_token_msg
    return jsonify({'host_info': jresults})

@app.route('/api/delete_hosts_v1.0', methods=['POST'])
@jwt_token_required
def delete_hosts(get_token_msg):
    if get_token_msg == "auth ok!":
        ins = Hosts()
        op_result = ins.delete_hosts()
    else:
        op_result = get_token_msg
    return  jsonify({"op_result": op_result})

@app.route('/api/add_hosts_v1.0', methods=['POST'])
@jwt_token_required
def add_hosts(get_token_msg):
    if get_token_msg == "auth ok!":
        ins = Hosts()
        op_result = ins.add_hosts()
    else:
        op_result = get_token_msg
    return jsonify({"op_result": op_result})

@app.route('/kafka/get_host_info_v1.1/<string:hostname>', methods=['POST'])
@jwt_token_required
def get_host_info(get_token_msg, hostname):
    if get_token_msg == "auth ok!":
        ins = Hosts()
        array = ins.get_host_info(hostname)
    else:
        array = get_token_msg
    return jsonify({'host_data': array})

@app.route('/api/open_wetty_v1.0', methods = ['POST'])
@jwt_token_required
def open_wetty(get_token_msg):
    if get_token_msg == "auth ok!":
        ins = Hosts()
        re = ins.open_wetty()
    else:
        re = get_token_msg
    return jsonify({"can_open_wetty": re})

@app.route('/api/remote_desktop_v1.0', methods = ['POST'])
@jwt_token_required
def show_remote_desktop(get_token_msg):
    if get_token_msg == "auth ok!":
        re = "ok"
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
    else:
        re = get_token_msg
    return re

"""-------------------------------------------------------------------------
基本功能

--------------------------------------------------------------------------"""

#设置根路由
@app.route('/')
def root():
    return app.send_static_file('login.html')

#404
@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Pages Not found'}), 404)

#登录认证
@app.route('/api/login_auth_v1.0', methods=['POST'])
def login_auth():
    ins = Jwt()
    rt_msg = ins.login_auth( request.json['username'], request.json['encrypt_password'] )
    if rt_msg == 1:
        rt_token = Jwt.jwt_visit_token[-1]
    elif rt_msg == -1:
        rt_token = "invalid token!"
    return jsonify({ "rt_token": rt_token })

"""-------------------------------------------------------------------------
页面访问前认证

--------------------------------------------------------------------------"""

#访问页面前认证
@app.route('/api/isauth_v1.0' , methods = ['POST'])
@jwt_token_required
def isauth(get_token_msg):
    if get_token_msg == "auth ok!":
        return jsonify({"rt_msg": get_token_msg})
    else:
        return jsonify({"rt_msg": "authorize failure!"})

"""-------------------------------------------------------------------------
Scripts

--------------------------------------------------------------------------"""
@app.route('/api/fetch_all_scripts_v1.0', methods = ['POST'])
@jwt_token_required
def fetch_all_scripts(get_token_msg):
    if get_token_msg == "auth ok!":
        ins = Scripts()
        re = ins.fetch_all_script_info()
    else:
        re = get_token_msg
    return jsonify({"script": re})

@app.route('/api/fetch_script_content_v1.0', methods = ['POST'])
@jwt_token_required
def fetch_script_content(get_token_msg):
    if get_token_msg == "auth ok!":
        script_name = request.json["script_name"]
        ins = Scripts()
        re = ins.fetch_script_content(script_name)
    else:
        re = get_token_msg
    return jsonify({"script_content": re})

@app.route('/api/new_or_import_script_v1.0', methods = ['POST'])
@jwt_token_required
def import_script(get_token_msg):
    if get_token_msg == "auth ok!":
        script_content = request.json['script_content']
        script_name = request.json['script_name']
        script_tags = request.json['script_tags']
        script_descript = request.json['script_description']
        ins = Scripts()
        re = ins.import_script( script_content, script_name, script_tags, script_descript )
    else:
        re = get_token_msg
    return jsonify({"import_script": re})

@app.route('/api/delete_script_v1.0', methods = ['POST'])
@jwt_token_required
def delete_script(get_token_msg):
    if get_token_msg == "auth ok!":
        select_script_names = request.json['select_script_names']
        ins = Scripts()
        re = ins.delete_script( select_script_names )
    else:
        re = get_token_msg 
    return jsonify({"delete_script_result": re})

#处理select2的脚本标签
@app.route('/api/fetch_all_script_tags_v1.0', methods = ['POST'])
@jwt_token_required
def fetch_all_script_tags(get_token_msg):
    if get_token_msg == "auth ok!":
        ins = Scripts()
        re = ins.fetch_all_script_tags()
    else:
        re = get_token_msg
    return jsonify({"script_tags": re})

#ace检查脚本语法
@app.route('/api/shell_syntax_check_v1.0', methods = ['POST'])
@jwt_token_required
def shell_syntax_check(get_token_msg):
    if get_token_msg == "auth ok!":
        script_content = request.json['script_content']
        ins = Scripts()
        re = ins.shell_syntax_check(script_content)
    else:
        re = get_token_msg
    return jsonify({"shell_check_result": re})

#修改脚本
@app.route('/api/modify_script_v1.0', methods = ['POST'])
@jwt_token_required
def modify_script(get_token_msg):
    if get_token_msg == "auth ok!":
        script_content = request.json['script_content']
        script_name = request.json['script_name']
        script_tags = request.json['script_tags']
        script_descript = request.json['script_description']
        script_old_name = request.json['script_old_name']
        ins = Scripts()
        re = ins.modify_script( script_content, script_name, script_tags, script_descript, script_old_name )
    else:
        re = get_token_msg
    return jsonify({"modify_script": re})

"""-------------------------------------------------------------------------
Processes

--------------------------------------------------------------------------"""

@app.route('/api/fetch_processes_content_v1.0', methods = ['POST'])
@jwt_token_required
def fetch_processes_content(get_token_msg):
    if get_token_msg == "auth ok!":
        processes_name = request.json["processes_name"]
        ins = Processes()
        re = ins.fetch_processes_content(processes_name)
    else:
        re = get_token_msg
    return jsonify({"processes_content": re})

@app.route('/api/add_processes_v1.0', methods = ['POST'])
@jwt_token_required
def add_processes(get_token_msg):
    if get_token_msg == "auth ok!":
        processes_name = request.json["processes_name"]
        processes_description = request.json["processes_description"]
        processes_tag = request.json["processes_tag"]
        selected_scripts = request.json['selected_scripts']
        ins = Processes()
        re = ins.add_processes(processes_name, processes_description, processes_tag, selected_scripts)
    else:
        re = get_token_msg
    return jsonify({"add_processes_result": re})

@app.route('/api/fetch_all_processes_v1.0', methods = ['POST'])
@jwt_token_required
def fetch_all_processes(get_token_msg):
    if get_token_msg == "auth ok!":
        ins = Processes()
        re = ins.fetch_all_processes_info()
    else:
        re = get_token_msg
    return jsonify({"fetch_all_processes_result": re})

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
