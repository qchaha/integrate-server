#!flask/bin/python3
from flask import json
from kafka import KafkaConsumer
from pymongo import MongoClient

if __name__ == '__main__':
    #创建kafka消费者
    #connect to Kafka server and pass the topic we want to consume
    consumer = KafkaConsumer('test', bootstrap_servers=['192.168.197.152:9092'])
    conn = MongoClient('192.168.197.152', 27017)
    #连接到test数据库
    db = conn['test']
    for message in consumer:
        #kafka消费队列消息，并且转换为json类型
        #message.value是byte类型，需要先用byte.decode函数转换为string类型，
        #然后再用json库的json.loads把string转换为list类型，最后使用jsonify函数返回json格式
        jmessage = json.loads(message.value.decode("utf-8"))
        #my_set对象指向test数据库下的XXX collection， 在这里XXX是获取的主机名
        my_set = db[jmessage['hostname']]
        #把数据插入到mongodb，以主机名进行分表（collection）
        my_set.insert(jmessage)
