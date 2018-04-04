#!../flask/bin/python3

import time
import datetime
from pymongo import MongoClient
import json

if __name__ == '__main__':
    #print(time.strftime( "%Y-%m-%d %H:%M:%S", time.localtime()) )
    conn = MongoClient('192.168.197.152', 27017)
    #连接到test数据库
    db = conn['test']
    collection= db['open']
    document = collection.find().sort([("date",-1)]).limit(1)
    array = []
    for i in document:
        break
    xaxis_end_time = datetime.datetime.strptime(i['date'], "%Y-%m-%d %H:%M:%S")
    xaxis_start_time = xaxis_end_time - datetime.timedelta(seconds=10)

    document = collection.find({"date": {"$gt": xaxis_start_time.strftime("%Y-%m-%d %H:%M:%S")}})
    for i in document:
        del i["_id"]
        #print(json.dumps(i))
        array.append(json.dumps(i))

    now = datetime.datetime.strptime(i['date'], "%Y-%m-%d %H:%M:%S")
    passed = now - datetime.timedelta(seconds=10)
    print(xaxis_start_time.strftime("%Y-%m-%d %H:%M:%S"))
    print("\r\n")
    print(xaxis_end_time.strftime("%Y-%m-%d %H:%M:%S"))
    print("\r\n")
