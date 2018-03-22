#!flask/bin/python
from flask import Flask,request,Response,abort,make_response,jsonify
from guacamole.client import GuacamoleClient 
import threading
import uuid
from geventwebsocket.handler import WebSocketHandler
from geventwebsocket import WebSocketError
from gevent.pywsgi import WSGIServer
from gevent import monkey
monkey.patch_all()
from time import ctime,sleep

app = Flask(__name__ , static_url_path = "")
#app.config['SECRET_KEY'] = 'secret!'


class Guac():
    ip = ''
    protocol = ''
    user = ''
    port = ''
    password = ''
    is_auth = False
    
    def __init__(self, ip ,protocol, port, user, password):
        self.GUACD_SERVER = '192.168.197.152'
        self.GUACD_PORT = 4822
        self.sockets = {}
        self.send_threads = {}
        self.recv_threads = {}
        self.sockets_lock = threading.RLock()
        self.read_lock = threading.RLock()
        self.write_lock = threading.RLock()
        self.pending_read_request = threading.Event()
        self.wss = {}
    
    def websockettunnel(self, ws):
        client = GuacamoleClient(self.GUACD_SERVER, self.GUACD_PORT)
        client.handshake(protocol=self.protocol,
                         hostname=self.ip,
                         port=self.port,
                         username=self.user,
                         password=self.password)
        cache_key = str(uuid.uuid4())

        send_thraed = threading.Thread(target=self.read_websocket,args=(cache_key, client, ws,))
        recv_thraed = threading.Thread(target=self.write_websocket,args=(cache_key, client, ws,))
        send_thraed.setDaemon(True)
        send_thraed.start()
        recv_thraed.setDaemon(True)
        recv_thraed.start()

        Guac.is_auth = False

        while True:
            sleep(10)


    def read_websocket(self, cache_key, client, ws):
        with self.read_lock:
            #pending_read_request.clear()
            while True:
                # instruction = '5.mouse,3.400,3.500;'
                instruction = client.receive()
                if instruction:
                    try:
                        ws.send(instruction)
                    except:
                        quit()
                        print("ws send instruction error")
                else:
                    quit()
                    sleep(0.01)
                    print("instruction is null")
            ws.send('0.;') 

    def write_websocket(self, cache_key, client, ws):
        with self.write_lock:
            while True:
                try:
                    chunk = ws.receive()
                    #instruction = '5.mouse,3.400,3.500;'
                    client.send(chunk)
                except:
                    quit()
                    print("aaaaaaaaaaaaaaa")
                    sleep(0.5)


@app.route('/api/guac_tunnel_v1.0')
def guac_tunnel():
    if Guac.is_auth:
        ws = request.environ.get('wsgi.websocket')
        if not ws:
            print("Expected WebSocket request")
        guac = Guac(Guac.ip, Guac.protocol, Guac.port, Guac.user, Guac.password)
        guac.websockettunnel(ws)
        print("going to exit tunnel!")
    else:
        print("authority is error!")
        abort(404)
    return "200";


@app.route('/api/guac_interface_v1.0', methods = ['POST'])
def guac_interface():
    Guac.ip = request.form["ip"]
    Guac.protocol = request.form["protocol"]
    Guac.user = request.form["user"]
    Guac.port = request.form["port"]
    Guac.password = request.form["password"]
    Guac.is_auth = True
    return "fff"

#404
@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Pages Not found'}), 404)

if __name__ == '__main__':
    #app.run(host='192.168.197.152',port=5001,debug=True,threaded=True)
    #socketio.run(app, host='192.168.197.152', port=5001, debug=True)
    app.debug = True
    #app.threaded = True
    http_server =WSGIServer(('192.168.197.152' , 5001), app, handler_class=WebSocketHandler)
    http_server.serve_forever()