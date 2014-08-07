#!/usr/bin/python2.7
# -*- coding:utf8 -*-
# vim: set fileencoding=utf8 

import os,sys,re,socket
import SocketServer,struct,socket,select
import paramiko,pygeoip
import ConfigParser
import sqlite3,atexit,time
#解析
#  |VER         | NMETHODS     | METHODS  |
#   x05             length         
#                                 X'00' NO AUTHENTICATION REQUIRED
#                                 X'01'  
#                                 X'02' USERNAME/PASSWORD
#                                 X'03' to X'7F' IANA ASSIGNED
#                                 X'80' to X'FE' RESERVED FOR PRIVATE METHODS
#                                 X'FF' NO ACCEPTABLE METHODS

# 合成
# |VER            | METHOD     |
#   x05               X'00' NO AUTHENTICATION REQUIRED
#                     X'01' GSSAPI
#                     X'02' USERNAME/PASSWORD
#                     X'03' to X'7F' IANA ASSIGNED
#                     X'80' to X'FE' RESERVED FOR PRIVATE METHODS
#                     X'FF' NO ACCEPTABLE M

#         |VER | CMD             |  RSV  | ATYP                 | DST.ADDR             | DST.PORT |
#         | 1  |  1              | X'00' |  1                   | Variable             |    2     |
#                  CONNECT X'01'
#                  BIND X'02'
#                  UDP ASSOCIATE X'03'
#                                          IP V4 address: X'01'
#                                          DOMAINNAME: X'03'        length+DST.ADDR
#                                          IP V6 address: X'04'


#     |VER | REP                                         |  RSV  | ATYP | BND.ADDR | BND.PORT |
#     | 1  |  1                                          | X'00' |  1   | Variable |    2     |
#             X'00' succeeded
#             X'01' general SOCKS server failure
#             X'02' connection not allowed by ruleset
#             X'03' Network unreachable
#             X'04' Host unreachable
#             X'05' Connection refused
#             X'06' TTL expired
#             X'07' Command not supported
#             X'08' Address type not supported
#             X'09' to X'FF' unassigned

class SocksV5Exception(Exception):
    reply=None              #直接发回错误
    msg='socks v5失败'

class SocksV5NoAcceptableAuthMethods(SocksV5Exception):
    reply=b'\x05\xFF'
    msg='不支持的验证方法'

class SocksV5SubException(SocksV5Exception):
    msg="socks v5 子过程失败"

class SocksV5AddressTypeNotSupported(SocksV5SubException):
    msg="不支持的地址类型"
    reply=b"\x05\x08\x00"
    
class SocksV5CommandNotSupported(SocksV5SubException):
    msg="不支持的地址类型"
    reply=b"\x05\x07\x00"
    
class SocksV5HostUnreachable(SocksV5SubException):
    msg="主机不可达"
    reply=b"\x05\x04\x00"
    
class SocksV5ConnectionRefused(SocksV5SubException):
    msg="链接被拒绝"
    reply=b'\x05\x05\x00'
    
def socksv5_select_auth(methods):
    '''
        完成身份认证
    '''
    if '\x02' in methods:
        return '\x02',None
    if '\x00' in methods:
        return '\x00',None
    else:
        raise SocksV5NoAcceptableAuthMethods

warning_list=[]
warning_db=sqlite3.connect(':memory:', check_same_thread=False)
warning_cur=warning_db.cursor()
with open('dump.sql','r') as f:
    warning_cur.executescript(f.read())
    warning_cur.close()
    warning_db.commit()
    


@atexit.register
def atexit_save_db():
    global warning_db
    print '写入硬盘'
    with open('dump.sql', 'w') as f:
        for line in warning_db.iterdump():
            f.write('%s\n' % line)

class InitSSHTunnel():
    def __init__(self,domain,port,username,password):
        self.domain=domain
        self.port=port
        self.username=username
        self.password=password
        self.retry=5
        self.connect()
    
    def connect(self):
        if self.retry:
            try: 
                conversation = paramiko.SSHClient()
                conversation.set_missing_host_key_policy(
                                        paramiko.WarningPolicy())
                conversation.connect(self.domain,
                                          port=self.port,
                                          username=self.username,
                                          password=self.password)
                self.conversation=conversation
                print 'ssh ',self.domain,'connect'
            except socket.timeout,e:
                self.retry-=1
                self.connect()
        else:
            raise SocksV5ConnectionRefused
                
    def getSocket(self,dest,src):
        trans=self.conversation.get_transport()
        res=trans.open_channel('direct-tcpip',dest,src)
        res.settimeout(5)
        return res
        
    def reflash(self):
        old=self.conversation
        self.connect()
        old.close()

sshtunnel=InitSSHTunnel('p5.fanfan8.com',22,'2012111001','299792458')

def socksv5_get_remote(cmd,atype,dest,src):
    '''
        返回远端socket接口
    '''
    global warning_db
    warning_cur=warning_db.cursor()
    query_res=warning_cur.execute('select query_t,block_t,block_ts,query_t,domain from warning where domain = ?',(dest[0],)).fetchone()
    if query_res:
        print query_res
        query_t,block_t,block_ts,query_t,domain=query_res
        if time.time()-block_ts<3600 and  block_t/query_t>0.8:  #有记录且上次失败在10小时内
            remote, raddr, rport = sshsocket(dest,src)
            return remote, b'\x01', socket.inet_aton(raddr), \
                        struct.pack(">H", rport) ,'ssh'
    else:
        warning_cur.execute('insert into warning(port,block_ts,domain) values(?,?,?)',(dest[1],time.time(),dest[0]))
    try_local=1
    warning_cur.execute('update warning set query_t = query_t +1 where domain=? and port = ?',(dest[0],dest[1]))
    while try_local:
        try:
            if cmd == '\x01':
                if atype in ['\x01','\x03']:
                    remote,raddr,rport = localsocket_ipv4(dest,src)
                elif atype == '\x04':
                    remote,raddr,rport = localsocket_ipv6(dest,src)
                else:
                    raise SocksV5AddressTypeNotSupported
                return remote, b'\x01', socket.inet_aton(raddr), \
                        struct.pack(">H", rport) ,'local'
        except socket.gaierror ,e:
            print '地址解析失败（%s:%s）'%(addr,port)
            warning_cur.execute('update warning set block_ts = ? ,block_t = block_t+1 where domain=? and port = ? ',(time.time(),dest[0],dest[1]))
            raise SocksV5HostUnreachable
        except socket.timeout ,e:
            try_local+=1
            print '超时重试',try_local
            warning_cur.execute('update warning set block_ts = ? ,block_t = block_t+1 where domain=? and port = ? ',(time.time(),dest[0],dest[1]))
            if try_local > 1 :
                print 'add',dest[0]
                if not dest[0] in warning_list:
                    warning_list.append(dest[0]);
                raise SocksV5HostUnreachable
    warning_cur.close()
    warning_db.commit()

def sshsocket(dest,src):
    global sshtunnel
    remote=sshtunnel.getSocket(dest, src)
    raddr,rport=remote.getpeername()
    print "IPv4_ssh",dest,raddr,rport,src
    return remote,raddr,rport
    
def localsocket_ipv4(dest=None,src=None):
    """
    创建本地代理
    """
    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote.settimeout(5)
    remote.connect(dest)
    raddr,rport = remote.getsockname()
    print 'IPv4:',dest,raddr,rport,src
    return remote,raddr,rport

def localsocket_ipv6(dest=None,src=None):
    """
    创建本地代理
    """
    remote = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    remote.settimeout(5)
    remote.connect((addr, port))
    raddr,rport = remote.getsockname()
    print 'IPv6:',dest,raddr,rport,src
    return remote,raddr,rport

class SocksStreamRequestHandler(SocketServer.StreamRequestHandler):      
    def handle(self):
        recv=self.request.recv(512)
        if recv[0]=='\x04':
            self.handle_socks4(recv)
        elif recv[0]=='\x05' :
            self.handle_socks5(recv)
        
    def handle_socks4(self,recv):
        pass
    
    def handle_socks5(self,recv):
        handle=''
        global warning_db
        warning_cur=warning_db.cursor()
        query_time=time.time()
        try:
            nmethod,=struct.unpack('b',recv[1:2])
            methods=recv[2:2+nmethod]
            method,authcallback=socksv5_select_auth(methods)
            self.request.send('\x05%s'%method)
            if callable(authcallback):
                authcallback()

            res=self.request.recv(4)
            _,cmd,_,atype=res
            if atype == '\x01':     #ipv4
                addr = socket.inet_ntoa(self.request.recv(4))
            elif atype == '\x03':   #domain
                addr = self.request.recv(ord(self.request.recv(1)[0]))
            elif atype == '\x04':   #ipv6
                addr = socket.inet_ntop(socket.AF_INET6, 
                                        self.request.recv(16))
            else:
                raise SocksV5AddressTypeNotSupported
            port = struct.unpack('>H',self.request.recv(2))[0]
            
            #获取远端socks 类型，地址，端口
            sp_remote,rtype,raddr,rport ,handle= \
                socksv5_get_remote(cmd,atype,
                                   (addr,port),
                                   self.request.getpeername())
            
            if rtype in ['\x01','\x04']:
                self.request.send('\x05\x00\x00%s%s%s'%(rtype,
                                                        raddr,
                                                        rport))
            elif rtype == '\x03':
                rlen=struct.pack('>H',len(raddr))
                self.request.send('\x05\x00\x00\x03%s%s%s'%(rlen,
                                                            raddr,
                                                            rport))
                del rlen
            while cmd == '\x01':
                r,w,e= select.select([self.request, sp_remote], 
                                     [], [])
                if self.request in r:
                    if sp_remote.send(self.request.recv(4096)) <= 0:
                        break  #向远端发送请求
                if sp_remote in r:
                    if self.request.send(sp_remote.recv(4096)) <= 0:
                        break  #向本地发送远端回复
                    
        
            warning_cur.execute('insert into history(host_name,port,query_time,response_time,handler) values(?,?,?,?,?)',
                                (addr,port,query_time,time.time(),handle))
        except socket.error,e:
            import sys
            warning_list.append(addr)
            warning_cur.execute('insert into history(host_name,port,query_time,response_time,handler,err) values(?,?,?,?,?,?)',
                                (addr,port,query_time,time.time(),handle,str(sys.exc_info())))
        except SocksV5Exception,e:
            import sys 
            warning_cur.execute('insert into history(host_name,port,query_time,response_time,handler,err) values(?,?,?,?,?,?)',
                                (addr,port,query_time,time.time(),handle,str(sys.exc_info())))
            if e.reply :
                self.request.send(e.reply)
            print e.msg
        finally:
            warning_cur.close()

try:
    server = SocketServer.ThreadingTCPServer(('localhost',4444), SocksStreamRequestHandler)
    server.serve_forever()
except (KeyboardInterrupt,EOFError),e:
    atexit_save_db()
    exit()
    server.shutdown()
    print 'shutdown'
    server.server_close()
    print 'server_close'
    
