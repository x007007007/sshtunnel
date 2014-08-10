#!/usr/bin/python2.7
# -*- coding:utf8 -*-
# vim: set fileencoding=utf8 

import SocketServer,struct,socket,select
import logging 
logger = logging.getLogger() 
hdlr = logging.FileHandler('sendlog.txt')
logger.addHandler(hdlr)

class SocksException(Exception): pass

class SocksIdentifyException(SocksException): pass
class SocksIdentifyFailed(SocksIdentifyException): pass
class SocksIdentifyDisabled(SocksIdentifyException): pass

class SocksNegotiateException(SocksException): pass
class SocksAddressTypeDisabled(SocksNegotiateException): pass

class SocksRemoteException(SocksException): pass
class SocksClientException(SocksException): pass


class SocksRequestHandler(SocketServer.StreamRequestHandler):
    @staticmethod
    def log(level, msg):
        pass #print level,msg
        
    @staticmethod 
    def get_socks5_connect_socket(dst,src,dst_type='\x01'):
        '''
            create remote connect and return socket of this connect
            dst is a tuple (addr,port) which is connect dst
            dst_type x01 is ipv4
                     x02 is host_name
                     x04 is ipv6   
            return remote_socket
        '''
        try:
            addr,port = dst
            if dst_type in ['\x01','\x03']:
                remote_atype = '\x01'
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.settimeout(5)
                remote.connect(dst)
            elif dst_type == '\x04':
                remote_atype = '\x04'
                remote = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                remote.settimeout(5)
                remote.connect(dst)
            return remote,remote_atype
        except socket.timeout,e:
            print 'timeout',e
        return None,None
            
    
    @staticmethod
    def get_socks5_bind_socket(dst,src,dst_type='\x01'):
        addr,port = dst
        if dst_type in ['\x01', '\x03']:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(5)
            remote.bind(('127.0.0.1', port+9000))
            remote.listen(0)
        elif dst_type == '\x04':
            remote = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            remote.bind(('::', port+9000))
            remote.listen(0)
        return remote
    
    @staticmethod 
    def get_socks5_udp_socket():
        pass
        
    def socks5_identifier(self,methods):
        '''socks v5 identificate active
            switch a identify method and finish methods
            if identify fail will raise Exception 
        '''
        if '\x00' in methods:
            self.request.send('\x05\x00')
            return True
        else:
            raise IdentifyDisabled,'Just support No authentication required'
            return False
        
    def handle(self):
        recv=self.request.recv(512)
        self.log('debug', 'recv msg:%r'%recv)
        if recv[0] == '\x04':
            self.handle_socks4(recv)
        elif recv[0] == '\x05' :
            
            self.handle_socks5(recv)
        
    def handle_socks4(self,recv):
        pass
    
    def handle_socks5(self,recv):
        def reply_client_bnd(atype,addr,port):
            '''
                返回成功创建链接后的BND信息
            '''
            self.log('debug', 'atype:%r ,(%s,%d)'%(atype,addr,port))
            if atype == '\x01' :    #ipv4
                msg='\x05\x00\x00\x01%s%s'%(socket.inet_aton(addr), struct.pack(">H", port))
            elif atype == '\x03' :   #domain
                msg='\x05\x00\x00\x03%s%s%s'%(struct.pack('>H', len(addr)), addr, struct.pack(">H", port))
            elif atype == '\x04':                   #ipv6
                msg='\x05\x00\x00\x04%s%s'%(socket.inet_pton(socket.AF_INET6,addr), struct.pack(">H", port))
            else:
                raise SocksAddressTypeDisabled
            self.log('debug', 'send to client:%r'%msg)
            self.request.send(msg)
        try:
            nmethod,=struct.unpack('b',recv[1:2])
            methods=recv[2:2+nmethod]
            self.socks5_identifier(methods)
            try:
                version,cmd,_,atype=self.request.recv(4)
            except ValueError,e:
                self.log('error','client send error request')
                self.log('debug','%r'%e)
                raise SocksClientException
            self.log('debug', 'recv msg:%r%r%r%r'%(version,cmd,_,atype))
            if atype == '\x01':     #ipv4
                addr = socket.inet_ntoa(self.request.recv(4))
            elif atype == '\x03':   #domain
                addr = self.request.recv(ord(self.request.recv(1)[0]))
            elif atype == '\x04':   #ipv6
                addr = socket.inet_ntop(socket.AF_INET6, self.request.recv(16))
            else:
                raise SocksAddressTypeDisabled
            port = struct.unpack('>H',self.request.recv(2))[0]
            self.log('notify','client request:(%s,%d)'%(addr,port))
            if cmd == '\x01':     #connect
                remote_sp,remote_atype = \
                    self.get_socks5_connect_socket((addr,port),
                                                   self.request.getpeername(),
                                                   atype)
                if remote_sp is None:return 
                bnd_addr,bnd_port = remote_sp.getpeername()
                self.log('notify', 'remote bnd:(%s,%d)'%(bnd_addr, bnd_port))
                reply_client_bnd(remote_atype,bnd_addr,bnd_port)
                while True:
                    r,w,e= select.select([self.request, remote_sp], [], [])
                    if self.request in r:
                        if remote_sp.send(self.request.recv(4096)) <= 0:
                            break  #向远端发送请求
                    if remote_sp in r:
                        if self.request.send(remote_sp.recv(4096)) <=0:
                            break  #向本地发送远端回复

            elif cmd == '\x02':   #bind
                pass
            elif cmd == '\x03':   #udp
                pass
        except SocksException,e:
            raise e;
        
server = SocketServer.ThreadingTCPServer(('127.0.0.1',4444), SocksRequestHandler)
server.serve_forever()
