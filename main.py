#!/usr/bin/python2.7
# -*- coding:utf8 -*-
# vim: set fileencoding=utf8 

import os,sys,re
import SocketServer,struct,socket,select
import paramiko,pygeoip
import ConfigParser

class SocksException(Exception): pass

class SocksRepliesException(SocksException):
    def __new__(cls,request,atype,code=None):
        if(not hasattr(cls,'code')):
            if(code==None):
                raise TypeError,'haven\'t set code'
            else:
                cls.code=code
    def __init__(self,request=None,atype='\x01',**other):
        self.request=request
        if hasattr(request,'send'):
            if atype == 'x01':
                request.send('\x05%s\x00\x01\x00\x00\x00\x00'%(self.code,))
            elif atype == 'x03':
                request.send('\x05%s\x00\x03\x00\x00'%(self.code,))
            else:
                request.send('\x05%s\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'%(self.code,))
        if not hasattr(self,'err_msg'):
            self.err_msg="SocksReplies error code: %s"%(self.code,)
    def __str__(self):
        return self.err_msg
    
class SocksGeneralServerException(SocksRepliesException):
    err_msg="general SOCKS server failure"
    code='\x01'

class SocksConnectionNotAllowedByRulesetException(SocksRepliesException):
    err_msg="connection not allowed by ruleset"
    code='\x02'

class SocksNetworkUnreachableException(SocksRepliesException):
    err_msg="Network unreachable"
    code='\x02'

class SocksHostUnreachableException(SocksRepliesException):
    err_msg="Host unreachable"
    code='\x04'

class SocksConnectionRefusedException(SocksRepliesException):
    err_msg="Connection refused"
    code='\x05'
        
class SocksTTLExpiredException(SocksRepliesException):
    err_msg="TTL expired"
    code='\x06'
        
class SocksCommandNotSupportedException(SocksRepliesException):
    err_msg="Command not supported"
    code='\x07'

class SocksAddressTypeNotSupportedException(SocksRepliesException):
    err_msg="Address type not supported"
    code='\x08'


        
class SocksManager():
    def __init__(self):
        pass
    

re_ip=re.compile('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
re_local=re.compile('.*?\.(?:baidu|sina|126|163|suhu|youku|tudou|douban|qq|qzone).*')
geofp=pygeoip.GeoIP(os.path.dirname(os.path.abspath(__file__))+'/data/GeoIPCountry.dat')


ssh_trans=None
client=None
def init_ssh():
    global ssh_trans,client
    client  = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.WarningPolicy())
    client.connect('p5.fanfan8.com',port=22,
                   username='2012111001', password='299792458')
    ssh_trans=client.get_transport()


def scoksv5_deal(request,hander,rfile):
    global re_ip,geofp,re_local
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
    if(re_ip.match(addr)):
        code=geofp.country_code_by_addr(addr)
        if code == 'CN':
            local_proxy(addr,port,request,mode)
            return
    elif(re_local.match(addr)):
        local_proxy(addr,port,request,mode)
        return
    ssh_proxy(addr,port,request,mode)
    
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
        raise SocksConnectionRefusedException()
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

def ssh_proxy(addr,port,request,mode):
    global ssh_trans
    try:
        reply = b"\x05\x00\x00\x01"
        if mode == 1:  # 1. Tcp connect
            try:
                remote=ssh_trans.open_channel('direct-tcpip',(addr,port),
                request.getpeername())
            except:
                pass
        else:
            reply = b"\x05\x07\x00\x01" # Command not supported 
            raise SocksCommandNotSupportedException()
        local = remote.getpeername()
        reply += socket.inet_aton(local[0]) + struct.pack(">H", local[1])  
    except socket.error: # Connection refused
        raise SocksConnectionRefusedException()
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
    
    def getProxy(self,atype,addr,port):
        if(atype in ['\x01','\x03']):
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.connect((addr, port))
            paddr,pport=remote.getsockname()
        elif(atype=='\x04'):        #ipv6
            remote = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            remote.connect((addr, port))
            paddr,pport,p1,p2=remote.getsockname()
        else:
            raise SocksAddressTypeNotSupportedException(self.request,atype)
        return paddr,pport,remote
    
    def socksv5deal(self):
        if '\x00' in self.socks_v5_methods: #不需要认证
            method='\x00'
        else:
            method='\xff'
        self.request.send('\x05%s'%method)
        _,cmd,_,atype = self.request.recv(4)
        
        if not cmd in ['\x01','x\02'] :
            send_err_code(atype,'\x07') #Command not supported
            
        if atype == '\x01': #ipv4
            address == self.request.recv(4)
            port = struct.unpack('>H',self.request.recv(2))[0]
        elif atype == '\x03': #domain
            address=self.request.recv(ord(self.request.recv(1)[0]))
            port = struct.unpack('>H',self.request.recv(2))[0]
        elif atype == '\x04': #ipv6
            address == self.request.recv(16)
            port = struct.unpack('>H',self.request.recv(2))[0]
        else: 
            raise SocksAddressTypeNotSupportedException(self.request,atype)
        
        try:
            paddr,pport,prequest=self.getProxy(atype,address,port)
            # self.request.send('\x05%s\x00%s')
            self.request.send('\x05\x00\x00\x01%s%s'%(
                            socket.inet_aton(paddr),
                            struct.pack(">H", pport)))
            while True:
                r, w, e = select.select([self.request, prequest], [], [])
                if self.request in r:
                    if prequest.send(self.request.recv(4096)) <= 0: break  #向远端发送请求
                if prequest in r:
                    if self.request.send(prequest.recv(4096)) <= 0: break  #向本地发送远端回复
        
        except SocksRepliesException,e:
            raise e
        #except Exception,e:
            #raise SocksGeneralServerException(self.request,atype)
        
        
class SshSocketProxy(object):
    ssh_except_times=0
    def __init__(self, host, username, password, port=22):
        self.logininfo={'host':host,
                        'username':username,
                        'password':password,
                        'port':port}
        self.client=self.new_client()
        self.ssh_trans=self.client.get_transport()

    def new_client(self):
        client  = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.WarningPolicy())
        client.connect(*(self.logininfo))
        return client


    def reflash_ssh_trans(self):
        print "重新链接ssh"
        self.client.close()
        self.client=self.new_client()
        self.ssh_trans=self.client.get_transport()
        self.ssh_except_times=0


    def get_socket(self,dest,src):
        trytime=0
        while trytime<20:
            trytiem+=1
            try:
                return self.ssh_trans.open_channel('direct-tcpip', 
                                                   dest, src)
            except SSHException:
                self.ssh_except_times+=1
                self.reflash_ssh_trans()
        
if __name__ == "__main__":
    #init_ssh()
    server = SocketServer.ThreadingTCPServer(('localhost',4444), SocksStreamRequestHandler)
    server.serve_forever()
    