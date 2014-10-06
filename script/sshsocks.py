#!/usr/bin/python2.7
# -*- coding:utf8 -*-
# vim: set fileencoding=utf8

from SocksService import ThreadingSocksServer,\
                         SocksSSHRemoteRequestHandler,\
                         SocksRequestHandler
import logging
import time
import os
import sys
import getopt
from ConfigParser import SafeConfigParser
from threading import Thread

class SockSockRun(object):
    
    home_config_path = '%s/.config/sshsocks.conf'%os.path.abspath(os.getenv('HOME'))
    
    def __init__(self):
        self.parse()
        try:
            args = sys.argv[1:]
            opts, args = getopt.getopt(args , "vhC", ['help', 'init-config', 'version'])
            for cmd, paramate in opts:
                if cmd in ('--help', '-h'):
                    self.help()
                    exit()
                elif cmd in ('--init-config', '-C'):
                    with open(self.home_config_path,'w') as h_cfg_fp:
                        with open(os.path.abspath("%s/../cfg/sshsocks.conf" % os.path.dirname(__file__)),'r') as cfg_fp:
                            h_cfg_fp.write(cfg_fp.read())
                    exit()
                elif cmd in ('--version', '-v'):
                    print 'alpha'
                    exit()
        except getopt.GetoptError:
            self.help()
            exit()
        self.run()

    @staticmethod
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

    def help(self):
        print "-h --help        get this"
        print "-C --init-config init config to $HOME"

    def parse(self):
        config = SafeConfigParser()
        config.read('%s/.config/sshsocks.conf'%os.path.abspath(os.getenv('HOME')))
        if 'TRUE' == config.get('log','enabled'):
            self.setlog(config.get('log', 'path'),int(config.get('log', 'level')))
        self.password = config.get('ssh', 'password')
        self.username = config.get('ssh', 'username')
        self.domain = config.get('ssh','domain')
        self.port = int(config.get('ssh','port'))
        self.server_port = int(config.get('server','port'))
        self.server_listen = config.get('server','listen')

    def run(self):
        sshtunnel = SocksSSHRemoteRequestHandler(self.domain,
                                                 self.username,
                                                 self.password,
                                                 self.port)
        server = ThreadingSocksServer(( self.server_listen,
                                        self.server_port),
                                        SocksRequestHandler,
                                        sshtunnel)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print 'server closing...'
            exit()



if __name__ == '__main__':
    client = SockSockRun()

