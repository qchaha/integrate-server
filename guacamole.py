#!flask/bin/python
from flask import Flask,request,Response,stream_with_context
from guacamole.client import GuacamoleClient 
import threading
import uuid

app = Flask(__name__ , static_url_path = "")

sockets = {}
sockets_lock = threading.RLock()
read_lock = threading.RLock()
write_lock = threading.RLock()
pending_read_request = threading.Event()

@app.route('/api/guac_tunnel_v1.0', methods = ['POST','GET'])
def guac_tunnel():
    rq = request.environ
    if rq['QUERY_STRING'] == "connect":
        #print(request)
        return _do_connect(request)
    else:
        tokens = rq['QUERY_STRING'].split(':')
        if len(tokens) >= 2:
            if tokens[0] == 'read':
                return _do_read(request, tokens[1])
            elif tokens[0] == 'write':
                return _do_write(request, tokens[1])
    return "400"

def _do_connect(request):
    # Connect to guacd daemon
    client = GuacamoleClient("192.168.197.152", 4822)
    client.handshake(protocol='vnc',
                     hostname="192.168.197.141",
                     port=15900,
                     #username="administrator",
                     password="admin")
    cache_key = str(uuid.uuid4())
    with sockets_lock:
        sockets[cache_key] = client

    res =Response(cache_key)
    return res

def _do_read(request, cache_key):
    pending_read_request.set()
    def content():
        with sockets_lock:
            client = sockets[cache_key]

        with read_lock:
            pending_read_request.clear()

            while True:
                # instruction = '5.mouse,3.400,3.500;'
                instruction = client.receive()
                if instruction:
                    yield instruction
                else:
                    break

                if pending_read_request.is_set():
                    #logger.info('Letting another request take over.')
                    break

            # End-of-instruction marker
            yield '0.;'
    res = Response(stream_with_context(content()))
    return res


def _do_write(request, cache_key):
    with sockets_lock:
        client = sockets[cache_key]

    with write_lock:
        while True:
            chunk = request.stream.read(8192)
            if chunk:
                client.send(chunk.decode())
            else:
                break

    res = Response(content_type='application/octet-stream')
    return res

if __name__ == '__main__':
    app.run(host='192.168.197.152',port=5001,debug=True,threaded=True)
