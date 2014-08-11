#!/usr/bin/python2.7
# -*- coding:utf8 -*-
# vim: set fileencoding=utf8

import logging, time
from ConfigParser import SafeConfigParser
from socksService import ThreadingSocksServer, SocksSSHRemoteRequestHandler, \
    SocksRequestHandler
    
def setlog(path,lvl=logging.DEBUG):
    logger = logging.getLogger() 
    logger.setLevel(logging.DEBUG)
    logger_hdlr = logging.FileHandler('sendlog.txt')
    logger_fmt = logging.Formatter('%(name)-12s %(asctime)s %(levelname)-8s %(message)s', '%a, %d %b %Y %H:%M:%S')
    logger_hdlr.setFormatter(logger_fmt)
    logger.addHandler(logger_hdlr)
    del logger_fmt,logger_hdlr
    def log(s, level, msg):
        map={
             'debug'    :logging.DEBUG,
             'error'    :logging.ERROR,
             'warning'  :logging.WARNING,
             'notify'   :logging.INFO,
             'info'     :logging.INFO,
             'critical' :logging.CRITICAL,
             }
        logger.log(map[level], msg)
    SocksRequestHandler.log=log 

config = SafeConfigParser()
config.read('sshtunnel.conf')
if 'TRUE'==config.get('log','enabled'):
    setlog(config.get('log','path'),int(config.get('log','level')))
password=config.get('ssh', 'password')
username=config.get('ssh', 'username')
domain=config.get('ssh','domain')
port=config.get('ssh','port')


sshtunnel=SocksSSHRemoteRequestHandler(domain, username, password, port)
print 'sshtunnel',sshtunnel.connect_handle

server = ThreadingSocksServer(('127.0.0.1',4444), SocksRequestHandler, sshtunnel)
server.serve_forever()