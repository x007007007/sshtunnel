#!/usr/bin/python2.7
# -*- coding:utf8 -*-
# vim: set fileencoding=utf8

from SocksService import ThreadingSocksServer, SocksSSHRemoteRequestHandler, \
    SocksRequestHandler

import logging, time, os
from ConfigParser import SafeConfigParser
    
def setlog(path, lvl=logging.DEBUG):
    logger = logging.getLogger() 
    logger.setLevel(logging.DEBUG)
    logger_hdlr = logging.FileHandler(path)
    logger_fmt = logging.Formatter('%(name)-12s %(asctime)s %(levelname)-8s %(message)s', '%a, %d %b %Y %H:%M:%S')
    logger_hdlr.setFormatter(logger_fmt)
    logger.addHandler(logger_hdlr)
    del logger_fmt, logger_hdlr
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

def help():
    print "-h --help        get this"
    print "-C --init-config init config to $HOME"

def run():
    config = SafeConfigParser()
    config.read('%s/.config/sshsocks.conf'%os.path.abspath(os.getenv('HOME')))
    if 'TRUE' == config.get('log','enabled'):
        setlog(config.get('log', 'path'),int(config.get('log', 'level')))
    password = config.get('ssh', 'password')
    username = config.get('ssh', 'username')
    domain = config.get('ssh','domain')
    port = int(config.get('ssh','port'))
    server_port = int(config.get('server','port'))
    server_listen = config.get('server','listen')
    
    sshtunnel = SocksSSHRemoteRequestHandler(domain, username, password, port)
    
    server = ThreadingSocksServer(( server_listen,server_port),
                                    SocksRequestHandler,
                                    sshtunnel)
    server.serve_forever()
    
if __name__ == '__main__':
    import sys,getopt
    try:
        args = sys.argv[1:]
        opts, args = getopt.getopt(args , "vhC", ['help', 'init-config', 'version'])
        for cmd, paramate in opts:
            if cmd in ('--help', '-h'):
                help()
                exit()
            elif cmd in ('--init-config', '-C'):
                import shutil
                home_config_path = '%s/.config/sshsocks.conf'%os.path.abspath(os.getenv('HOME'))
                shutil.copy('cfg/sshsocks.conf', home_config_path)
                exit()
            elif cmd in ('--version', '-v'):
                print 'alpha'
                exit()
    except getopt.GetoptError:
        help()
        exit()
    
run()

