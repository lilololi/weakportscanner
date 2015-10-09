#!/usr/bin/ python
# -*- encoding: utf-8 -*-
#weak path scanner
#__author=Sevsea
import optparse
import os
import sys
import time
from optparse import OptionParser
from multiprocessing.dummy import Pool as ThreadPool
import nmap



def check_hosts(hosts):
    checkin=[]
    try:
        ret=os.popen("ping %s -c 2 -W1"%hosts)
        if "1 received" in ret.read() or "2 received" in ret.read():
            if hosts not in checkin:
                checkin.append(hosts)
        else:
            pass
        return "".join(checkin)
    except Exception,e:
        print e
        pass

def nmapscan(hosts):
    host_list=[]
    try:
        print "try:%s"%hosts
        nm=nmap.PortScanner()
        #nm.scan(hosts=hosts,arguments='-sS -Pn -p 21-65535')
        #choose one
        nm.scan(hosts=hosts,arguments='-sS -Pn -p 21,22,69,79,80,161,443,873,1433,2049,2181,3306,3389,6379,7001,8080')
        for host in nm.all_hosts():
            print ('------------------------------------------')
            host_name=host_list
            print('host : %s state : %s' % (host,nm[host].state()))

            for proto in nm[host].all_protocols():
                lport=nm[host][proto].keys()
                for port in lport:
                    if nm[host][proto][port]['state'] =="open": #or nm[host][proto][port]['state']=="filtered":
                        print('port : %s state : %s' % (port, nm[host][proto][port]['state']))
                    else:
                        pass
            time.sleep(1)
    except Exception,e:
        print e
        pass


class weakscanner:
    def __init__(self,domainfile):
        self.domainfile=domainfile
        self.load_subhosts()
        self.run()

    def load_subhosts(self):
        hosts=[]
        with open(self.domainfile) as h:
            for line in h:
                sub_hosts=line.strip()
                if sub_hosts not in hosts and sub_hosts!="":
                    hosts.append(sub_hosts)
        self.hosts=hosts
        try:
            pool=ThreadPool(50)
            host_List=pool.map(check_hosts,self.hosts)
            pool.close()
            pool.join()
        except Exception,e:
            print e
            pass
        while '' in  host_List:
            host_List.remove('')
        self.host_List=host_List
        print self.host_List

    def run(self):
        try:
            pool=ThreadPool(50)
            port_list=pool.map(nmapscan,self.host_List)
            pool.close()
            pool.join()
        except Exception,e:
            print e



if __name__=='__main__':
    parser=optparse.OptionParser('usage:python weakscanner.py -d {domainfile.txt}')
    parser.add_option('-d','--domainfile',dest='domainfile',default=None,type='string')
    (options,args)=parser.parse_args()
    if options.domainfile!=None and args==[]:
        weakscanner(options.domainfile)
    elif options.domainfile==None and args!=[]:
        print "args"
    else:
        parser.print_help()
        sys.exit(0)