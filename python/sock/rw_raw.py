#!/usr/bin/python
# ---coding:utf-8---
# desp:收到socket原始数据
import socket

#
def _send_to(source_ip='127.0.0.1', port=9000, msg='hello'):
    # create a raw socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error, msg:
        print 'Socket could not be create, Error Code: ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()

#main entry
if __name__=='__main__':
    _send_to()
