#!../flask/bin/python

import pymysql
import time

class Processes:
    def __init__(self):
        self.mysql_srvip = '192.168.197.152' 
        self.mysql_user = 'root' 
        self.mysql_pwd = 'root123' 
        self.mysql_db_name = 'integrate'
        self.sql_fetch_processes_content = "select a.p_name, a.s_name, a.sequence, b.description script_description from processes_scripts_map a, script b where a.p_name = '{0}' and a.s_name = b.name order by sequence"
        self.sql_fetch_all_processes = "select name,description,tag from processes"

    def fetch_processes_content(self, processes_name):
        db = pymysql.connect(self.mysql_srvip, self.mysql_user, self.mysql_pwd, self.mysql_db_name, charset="utf8")
        cursor = db.cursor()
        sql = self.sql_fetch_processes_content.format(processes_name)
        #print(sql)
        try:  
            cursor.execute(sql)  
            results = cursor.fetchall()
            jresults = []
            for result in results:
                dresults = {}
                dresults['p_name'] = result[0]
                dresults['s_name'] = result[1]
                dresults['sequence'] = result[2]
                dresults['script_description'] = result[3]
                jresults.append(dresults)
            db.close()
        except:
            return "fetch processes content from mysql error"
        if jresults == []:
            return "can not fetch any processes!"
        return jresults 

    def add_processes(self, name, description, tag, selected_scripts):
        db = pymysql.connect(self.mysql_srvip, self.mysql_user, self.mysql_pwd, self.mysql_db_name, charset="utf8")
        cursor = db.cursor()
        sql_insert_processes = "insert into processes values(null, '{0}', '{1}', '{2}')".format(name, description, tag)
        sequence = 1
        try:
            cursor.execute(sql_insert_processes)
            for script in selected_scripts:
                sql_update_script = "insert into processes_scripts_map values(null, '{0}', '{1}', '{2}', '{3}')".format(name, script['name'], sequence, time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
                cursor.execute(sql_update_script)
                sequence += 1
                #print(sql_update_script)
            db.commit()
            db.close()
        except:
            print("error insert data to add_processes from mysql!")
            abort(404)
        return "add_processes_successful"

    def fetch_all_processes_info(self):
        db = pymysql.connect(self.mysql_srvip, self.mysql_user, self.mysql_pwd, self.mysql_db_name, charset="utf8")
        cursor = db.cursor()
        try:
            cursor.execute(self.sql_fetch_all_processes)
            results = cursor.fetchall()
            jresults = []
            for result in results:
                dresults = {}
                dresults['name'] = result[0]
                dresults['description'] = result[1]
                dresults['tag'] = result[2]
                jresults.append(dresults)
            db.close()
        except:
            print("error fetch in all_processes_data from mysql!")
            abort(404)
        return jresults