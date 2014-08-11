#!/usr/bin/python2.7
# -*- coding:utf8 -*-
# vim: set fileencoding=utf8 
import sys
sys.path.append('./src')
import SocketServer, struct, socket, select, paramiko

class SocksException(Exception): pass 
class SocksIdentifyException(SocksException): pass
class SocksIdentifyFailed(SocksIdentifyException): pass
class SocksIdentifyDisabled(SocksIdentifyException): pass
class SocksNegotiateException(SocksException): pass
class SocksAddressTypeDisabled(SocksNegotiateException): pass
class SocksRemoteException(SocksException): pass
class SocksClientException(SocksException): pass


class SocksRequestHandler(SocketServer.StreamRequestHandler):
    def log(self, level, msg):
        pass #print level,msg
         
    def get_socks5_connect_socket(self,dst,src,dst_type='\x01'):
        '''
            create remote connect and return socket of this connect
            dst is a tuple (addr,port) which is connect dst
            dst_type x01 is ipv4
                     x02 is host_name
                     x04 is ipv6   
            return remote_socket
        '''
        if (hasattr(self, 'server') and 
            hasattr(self.server, 'socks') and 
            hasattr(self.server.socks, 'connect_handle') and
            callable(self.server.socks.connect_handle)):
            return self.server.socks.connect_handle(dst,src,dst_type)
        return None,None 
    
    def get_socks5_bind_socket(self,dst,src,dst_type='\x01'):
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
    
    def get_socks5_udp_socket(self,dst,src,dst_type='\x01'):
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
        def exchange_data(remote_peer,local_peer,debug=None):
            '''
                交换连个tcp链接的数据
            '''
            while True:
                r,w,e= select.select([remote_peer, local_peer], [], [])
                if remote_peer in r:
                    try:
                        recv=remote_peer.recv(4096)
                    except (socket.error,socket.timeout), e:
                        raise SocksRemoteException,e.message
                    try:
                        if local_peer.send(recv) <=0:
                            break  #向本地发送远端回复
                    except (socket.error,socket.timeout), e:
                        raise SocksClientException, e.message
                if local_peer in r:
                    try:
                        recv=local_peer.recv(4096)
                    except (socket.error,socket.timeout), e:
                        raise SocksClientException, e.message
                    try:
                        if remote_peer.send(recv) <= 0:
                            break  #向远端发送请求
                    except (socket.error,socket.timeout), e:
                        raise SocksRemoteException,e.message
                    
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
                if remote_sp is None:return #没有获取到远端socket
                try:
                    bnd_addr,bnd_port = remote_sp.getpeername()
                except socket.error, e:
                    raise SocksRemoteException, e
                self.log('notify', 'connect remote bnd:(%s,%d)'%(bnd_addr, bnd_port))
                reply_client_bnd(remote_atype,bnd_addr,bnd_port)
                exchange_data(remote_sp,self.request)
            elif cmd == '\x02':   #bind
                remote_sp,remote_atype = \
                    self.get_socks5_bind_socket((addr,port),
                                                   self.request.getpeername(),
                                                   atype)
                if remote_sp is None:return 
                try:
                    bnd_addr,bnd_port = remote_sp.gethostname()
                except socket.error, e:
                    raise SocksRemoteException, e
                self.log('notify', 'bind remote bnd:(%s,%d)'%(bnd_addr, bnd_port))
                reply_client_bnd(remote_atype,bnd_addr,bnd_port)
                exchange_data(remote_sp,self.request)
            elif cmd == '\x03':   #udp
                pass
        except SocksException,e:
             self.log('warning','SocksException:%s'%e.message)
#         except socket.error,e:
#             print 'socket.error',e.message


class SocksRemoteRequestHandler(object):

    def connect_handle(self, dst, src, dst_type='\x01'):
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
            print 'timeout',dst,src,e.message
        except socket.error,e:
            print 'socket error',dst,src,error.socket.e.message
        return None,None
    
    def bind_handle(self, dst, src, dst_type='\x01'):
        return None,None
    
    def udp_handle(self, dst, src, dst_type='\x01'):
        return None,None


class SocksSSHRemoteRequestHandler(SocksRemoteRequestHandler):
    old_conversation=None
    errnum=0
    reconnectnum=0
    def __init__(self, domain, username, password, port=22):
        self.domain=domain
        self.username=username
        self.password=password
        self.port=port

    def get_conversation(self):
        conversation = paramiko.SSHClient()
        conversation.set_missing_host_key_policy(paramiko.WarningPolicy())
        try:
            conversation.connect( self.domain,
                                  port=self.port,
                                  username=self.username,
                                  password=self.password)
        except socket.gaierror , e :
            raise SocksRemoteException, '链接代理失败'
        except paramiko.AuthenticationException, e:
            raise SocksRemoteException, '用户认证失败'
        except paramiko.BadHostKeyException, e:
            raise SocksRemoteException, 'Host Key 验证失败'
        return conversation
    
    def get_socket(self,conversation,dst,src):
        try:
            trans=conversation.get_transport()
            res=trans.open_channel('direct-tcpip', dst, src)
            res.settimeout(5)
            return res
        except paramiko.ChannelException,e:
            print 'retry %s:%d'%dst
            try:
                trans=conversation.get_transport()
                res=trans.open_channel('direct-tcpip', dst, src)
                res.settimeout(5)
                return res
            except paramiko.ChannelException,e:
                self.errnum+=1
                raise SocksRemoteException, e.message
        
    
    def connect_handle(self, dst, src, dst_type='\x01'):
        if self.old_conversation is None:
            self.old_conversation = self.get_conversation()
        try:
            socket=self.get_socket(self.old_conversation, dst, src)
            self.reconnectnum=0
        except paramiko.SSHException, e:
            if not self.reconnectnum>5: 
                self.reconnectnum+=1
                self.old_conversation=self.get_conversation()
                return self.connect_handle(dst, src, dst_type)
            else:
                raise SocksRemoteException, '多次重试无效'
        return socket,'\x01'
    
    
class SocksServer(SocketServer.TCPServer): 
    def __init__(self, server_address, RequestHandlerClass, TunnelHandler, bind_and_activate=True):
        if isinstance(TunnelHandler,SocksRemoteRequestHandler):
            self.socks=TunnelHandler
        else:
            raise SocksRemoteException
        SocketServer.TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)


class ThreadingSocksServer(SocketServer.ThreadingMixIn, SocksServer): pass


class ForkingSocksServer(SocketServer.ForkingMixIn, SocksServer): pass


