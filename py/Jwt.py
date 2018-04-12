#!..flask/bin/python

from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
import pymysql
import time


class Jwt:

    #静态变量，保存jwt,类内访问时需要Jwt.jwt_token
    jwt_visit_token = []

    def __init__( self ):
        self.mysql_srvip = "192.168.197.152"
        self.mysql_user = "root"
        self.mysql_pwd = "root123"
        self.mysql_db_name = "test"
        self.jwt_secret_key = "verify_complex"
        self.jwt_salt_key = "auth_salt_verylong"
        self.jwt_visit_expire_time = 3600

    
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
        rt_token = s.dumps( { "role" : "admin" , "user" : "root", "iat": timestamp } ).decode("utf-8")            
        return rt_token

    """JWT 校验token"""
    def verify_token( self ):
        s = Serializer( secret_key = self.jwt_secret_key, salt = self.jwt_salt_key )
        #print(request.json['token'])
        #print(Jwt.jwt_token)
        try:
            data = s.loads(Jwt.jwt_token)
        #token expired
        except SignatureExpired:
            return "token expired!"
        #invalid token
        except BadSignature:
            return "invalid token! signature may be modified!"
        except:
            return "token require error!"
        return data

    """认证身份，认证成功才生成JWT，返回1则代表成功，进行跳转；返回-1则表示失败，重新输入"""
    def login_auth( self, r_admin_user, r_encrypt_password ):
        db = pymysql.connect( self.mysql_srvip, self.mysql_user, self.mysql_pwd, self.mysql_db_name )
        cursor = db.cursor()
        try:
            cursor.execute("select admin_user, admin_password from host where admin_user = 'root' and ip_address='192.168.197.152'")
            results = cursor.fetchall()
            for result in results:
                admin_user = result[0]
                encrypt_password = result[1]
            db.close()
        except:
            print("error fetch in admin password from mysql!")
            abort(404)

        if r_encrypt_password == encrypt_password and admin_user == r_admin_user:
            Jwt.jwt_visit_token.append(self.generate_token())
            rt_msg = 1
        else:
            #Jwt.jwt_visit_token = "login auth failure!"
            rt_msg = -1
        #print("visit_token: " + Jwt.jwt_visit_token)
        return rt_msg