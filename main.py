#!/usr/bin/python2.7
# -*- coding:utf8 -*-
# vim: set fileencoding=utf8 

import os,sys
import SocketServer,struct,socket,select
import paramiko

def scoksv5_deal(request,hander,rfile):
    request.send(b'\x05\x00')
    data = rfile.read(4)  
    mode = ord(data[1])
    addrtype = ord(data[3])
    if addrtype == 1:
        addr = socket.inet_ntoa(rfile.read(4))
    elif addrtype == 3:     # Domain name  
        addr = rfile.read(ord(request.recv(1)[0])) 
    port = struct.unpack('>H', rfile.read(2))[0]
    print addr,port
    local_proxy(addr,port,request,mode)
    
def local_proxy(addr,port,request,mode):
    try:
        reply = b"\x05\x00\x00\x01"
        if mode == 1:  # 1. Tcp connect
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.connect((addr, port))  
        else:
            reply = b"\x05\x07\x00\x01" # Command not supported  
        local = remote.getsockname()
        reply += socket.inet_aton(local[0]) + struct.pack(">H", local[1])  
    except socket.error: # Connection refused
        reply=b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00'
    request.send(reply)
    if reply[1] == '\x00':  # Success
        if mode == 1:
            while True:
                r, w, e = select.select([request, remote], [], [])
                if len(r) > 1 : print len(r)
                if request in r:
                    if remote.send(request.recv(4096)) <= 0: break  #向远端发送请求
                if remote in r:
                    if request.send(remote.recv(4096)) <= 0: break  #向本地发送远端回复


class SocksStreamRequestHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        data=self.request.recv(655350)
        if data[0]==struct.pack('c','\x05'):
            print "socks v5接入"
            scoksv5_deal(self.request,data,self.rfile)
        elif data[0]==struct.pack('c','\x04'):
            print "socks v4暂不支持"
            self.request.close()
    

if __name__ == "__main__":
    server = SocketServer.ThreadingTCPServer(('localhost',4444), SocksStreamRequestHandler)
    server.serve_forever()
    