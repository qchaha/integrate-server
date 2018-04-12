#!../flask/bin/python
from flask import abort
import os
import pymysql
import subprocess
import json
import time


class Scripts:


    def __init__(self):
        self.script_path = '/root/py/integrate-server/scripts/'
        self.script_trash_path = '/root/py/integrate-server/scripts/scripts_trash/'
        self.script_type = 'shell'
        self.mysql_srvip = '192.168.197.152' 
        self.mysql_user = 'root' 
        self.mysql_pwd = 'root123' 
        self.mysql_db_name = 'integrate'
        self.sql_fetch_all_script = 'select name,type,tag,description from script'
        self.sql_fetch_script_content = "select path from script where name = '"
    
    def fetch_script_content(self, name):
        script_content = []
        path = ""
        db = pymysql.connect(self.mysql_srvip, self.mysql_user, self.mysql_pwd, self.mysql_db_name, charset="utf8")
        cursor = db.cursor()
        sql = self.sql_fetch_script_content + name + "'"
        try:  
            cursor.execute(sql)  
            results = cursor.fetchall()
            for result in results:
                path = result[0]
            db.close()
            with open(path, 'rt', encoding='utf-8') as f:
                for line in f:
                    #print(line)
                    script_content.append(line)
        except:
            print("error on fetch script content!")
            return "can not fetch any script content!"
        return script_content
    
    def fetch_all_script_info(self):
        db = pymysql.connect(self.mysql_srvip, self.mysql_user, self.mysql_pwd, self.mysql_db_name, charset="utf8")
        cursor = db.cursor()
        try:
            cursor.execute(self.sql_fetch_all_script)
            results = cursor.fetchall()
            jresults = []
            for result in results:
                dresults = {}
                dresults['name'] = result[0]
                dresults['type'] = result[1]
                dresults['tag'] = result[2]
                dresults['description'] = result[3]
                jresults.append(dresults)
            db.close()
        except:
            print("error fetch in script_data from mysql!")
            abort(404)
        return jresults

    def add_script(self):
        db = pymysql.connect(self.mysql_srvip, self.mysql_user, self.mysql_pwd, self.mysql_db_name, charset="utf8")
        cursor = db.cursor()
        a="insert into script values(null,'/root/py/integrate-server/scripts/test3.sh','shell','"
        a= a + "第三次测试"
        a= a + "',null,null,'shell#version upgrade#auto#')"
        #print(a.encode("utf-8"))
        try:
            cursor.execute(a)
            db.commit()
            db.close()
        except:
            print("error insert data to add_script from mysql!")
            abort(404)
        return "ff"

    def import_script(self, script_content, script_name, script_tags, script_descript):
        full_path = self.script_path + script_name
        #判断文件是否存在
        if os.path.exists(full_path) == True:
            return "script already exitst,please change script name"
        try:
            with open(full_path, 'wt', encoding='utf-8') as f:
                f.write(script_content)
        except:
            print("error in writing import script!")
            abort(404)
        db = pymysql.connect(self.mysql_srvip, self.mysql_user, self.mysql_pwd, self.mysql_db_name, charset="utf8")
        cursor = db.cursor()
        sql = "insert into script values(null,'{0}','shell','{1}',null,null,'{2}','{3}')".format(full_path, script_name, script_tags, script_descript)
        #print(a.encode("utf-8"))
        try:
            cursor.execute(sql)
            db.commit()
            db.close()
        except:
            print("error insert data to import_script from mysql!")
            abort(404)
        return "import_script_successful"

    def fetch_all_script_tags(self):
        db = pymysql.connect(self.mysql_srvip, self.mysql_user, self.mysql_pwd, self.mysql_db_name, charset="utf8")
        cursor = db.cursor()
        sql = "select tag_name from script_tags"
        id = 0
        jresults = []
        try:
            cursor.execute(sql)
            results = cursor.fetchall()
            for result in results:
                did = {}
                did['id'] = id
                id += 1
                dresults = {}
                dresults['text'] = result[0]
                combination = did
                combination.update(dresults)
                jresults.append(combination)
            db.close()
        except:
            print("error in fetch all script tags!")
            abort(404)
        return jresults

    def delete_script(self, select_script_names):
        names = ""
        for name in select_script_names:
            names = "\'" + name + "\'," + names
            cmd = "/bin/mv " + self.script_path + name +  " " + self.script_trash_path + name + time.strftime("_%Y%m%d%H%M%S", time.localtime())
            try:
                subprocess.call(cmd,shell=True,stdout=open('/dev/null','w'),stderr=subprocess.STDOUT)
            except:
                print("delete script error")
                abort(404)
        #print(names)
        names = names[:-1]
        db = pymysql.connect(self.mysql_srvip, self.mysql_user, self.mysql_pwd, self.mysql_db_name, charset="utf8")
        cursor = db.cursor()
        sql = "delete from script where name in (" + names + ")"
        try:
            cursor.execute(sql)
            db.commit()
            db.close()
        except:
            print("delete from database record error")
            abort(404)
        return "delete complete!"

    def shell_syntax_check(self, script_content):
        """
        把脚本内容直接在管道中处理，不写到操作系统的文件上
        1.正常的情况下，需要按这样的格式来调用shellcheck：
            shellcheck -f json script_name
          这样有个问题，需要script_name落地到操作系统上，为了解决这个问题，我是用管道的方法
        2.使用管道，我可以这样操作:
            cat script_name | shellcheck -f json -
          这样只需要我把script_name作为Popen的标准输入stdin，就能达到目的
        3.这里使用subprocess的communicate方式指定管道输入
        """

        process_shellcheck = subprocess.Popen('shellcheck -f json -', shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        tuple_results = process_shellcheck.communicate(input=script_content.encode("utf-8"))[0]
        """
        类型转换：
        元组转str： tuple_results.__str__()
        str转bytes： eval
        bytes转list： json.loads
        """
        json_results = json.loads(tuple_results)
        #print(json_results)
        return json_results

    def modify_script(self, script_content, script_name, script_tags, script_descript, script_old_name):
        full_path = self.script_path + script_old_name
        #判断文件是否存在
        if os.path.exists(full_path) == False:
            return "script is not exitst, please contact your administrator"
        else:
            cmd = "/bin/mv " + self.script_path + script_old_name +  " " + self.script_trash_path + script_old_name + time.strftime("_%Y%m%d%H%M%S", time.localtime())
            try:
                subprocess.call(cmd,shell=True,stdout=open('/dev/null','w'),stderr=subprocess.STDOUT)
            except:
                print("backup modify script error")
                abort(404)
            try:
                with open(self.script_path + script_name, 'wt', encoding='utf-8') as f:
                    f.write(script_content)
            except:
                print("error in writing modify script!")
                abort(404)
            db = pymysql.connect(self.mysql_srvip, self.mysql_user, self.mysql_pwd, self.mysql_db_name, charset="utf8")
            cursor = db.cursor()
            sql = "update script set path='{0}',name='{1}',tag='{2}',description='{3}' where name='{4}'".format(self.script_path + script_name, script_name, script_tags, script_descript, script_old_name)
            #print(a.encode("utf-8"))
            try:
                cursor.execute(sql)
                db.commit()
                db.close()
            except:
                print("error insert data to modify_script from mysql!")
                abort(404)
        return "modify_script_successful"

