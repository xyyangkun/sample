#!/usr/bin/python
# ---coding:utf-8---
# desp:收到socket原始数据
import socket
import sys


# send fun
def _send_to(source_ip='127.0.0.1', port=9000, msg='hello'):
    # create a raw socket
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    except socket.error, msg:
        print 'Socket could not be create, Error Code: ' + \
            str(msg[0]) + ' Message ' + msg[1]
        sys.exit()

    # http://stackoverflow.com/questions/1117958/how-do-i-use-raw-socket-in-python
    # bind may be eth0
    s.bind(("eno16777736", 0))

    src_addr = "\x01\x02\x03\x04\x05\x06"
    dst_addr = "\x01\x02\x03\x04\x05\x06"
    payload = ("["*30)+"PAYLOAD"+("]"*30)
    checksum = "\x1a\x2b\x3c\x4d"
    ethertype = "\x08\x01"

    s.send(dst_addr+src_addr+ethertype+payload+checksum)


# main entry
if __name__ == '__main__':
    # 使用前应该先运行这个命令：sudo ethtool -K eth1 tx off
    # 我是在虚拟机中测试的可以抓到一个以太网包
    # 使用命令抓包：
    # sudo tcpdump -i eno16777736 -nn -c 10
    # sudo tcpdump -i eno16777736 -x
    # 为了防止干扰最好把网线拔了
    _send_to()
