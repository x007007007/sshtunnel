#!/usr/bin/python2.7
# -*- coding:utf8 -*-
# vim: set fileencoding=utf8 

import os,sys,re
import SocketServer,struct,socket,select
import paramiko,pygeoip
import ConfigParser

class SocksStreamRequestHandler(SocketServer.StreamRequestHandler):
    socks_v5_methods=[]
    def handle(self):
        data=self.request.recv(512) # socksv5 max 257 : VER 1 | NMETHODS 1 | METHODS 255
        version,extinfo=struct.unpack('bb',data[:2])
        if version==5:
            if extinfo>0:
                self.socks_v5_methods=data[2:2+extinfo]
            self.socksv5deal()
        elif version==4:
            print "socks v4暂不支持"
            self.request.close()
        else:
            print '未知接入'
            self.request.close()
    
    def socksv5deal(self):
        
        
        
        
class SocksService():
    def __init__(self,host='localhost',port=1080):
        self._listenhost=host
        self._listenport=1080
        self.server = SocketServer.ThreadingTCPServer((host,port),SocksStreamRequestHandler)