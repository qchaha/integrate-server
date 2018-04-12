#!/usr/bin/python
# coding: utf8


from __future__ import print_function
import requests
import json


class ZbxSdkException(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg


class ZbxSdk(object):
    def __init__(self, host, user, passwd):
        self._id = 1
        self._url = 'http://' + host + '/api_jsonrpc.php'
        self._auth = self.login(user, passwd)

    def request(self, post_data):
        self._id += 1
        method = post_data.get('method')
        headers = {'Content-Type': 'application/json-rpc',
                   'User-Agent': 'python/zbx_sdk'}
        res = requests.post(self._url, json=post_data, headers=headers)
        try:
            content = res.json()
        except json.decoder.JSONDecodeError:
            raise ZbxSdkException(res.text)
        try:
            return content['result']
        except KeyError:
            msg = '\n\tmethod: %s\n' % method
            for k, v in content.get('error').items():
                msg += '\t%s: %s\n' % (k, v)
            raise ZbxSdkException(msg)

    def set_obj(self, method, params):
        obj = {
            'jsonrpc': '2.0',
            'method': method,
            'params': params,
            'id': self._id,
        }
        if method not in ('user.login', 'apiinfo.version'):
            obj['auth'] = self._auth
        return obj

    def login(self, user, passwd):
        """
        https://www.zabbix.com/documentation/3.0/manual/api
        return auth id
        :param user: (str) api user
        :param passwd: (str) api passwd
        :return: (str) auth id
        """
        method = 'user.login'
        params = {'user': user,
                  'password': passwd}
        obj = self.set_obj(method, params)
        return self.request(obj)

    def run(self, method, **kwargs):
        """
        通用方法
        :param method:
        :param kwargs:
        :return:
        """
        if kwargs.get('params'):
            obj = self.set_obj(method, kwargs.get('params'))
            return self.request(obj)
        params = {}
        if kwargs:
            for k, v in kwargs.items():
                params[k] = v
        obj = self.set_obj(method, params)
        return self.request(obj)


def test():
    import json
    host = 'xxx'
    user = 'xxx'
    passwd = 'xxx'
    zbx = ZbxSdk(host=host, user=user, passwd=passwd)
    res = zbx.run('host.get', filter={'host': ['xxx']})
    print(json.dumps(res, ensure_ascii=False, indent=4))


if __name__ == '__main__':
    test()
