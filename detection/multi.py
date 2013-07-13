#!/usr/bin/env python

from multiprocessing import Process
from scapy.all import *
import random

def f(string):
    out=sniff(filter=string, iface="eth0", prn=lambda x:x.summary(), timeout=2)
    a=random.randint(1,20)
    wrpcap(str(a),out)

#if __name__=="__main__":
def skata(function, **args):
    # not complete yet
    p=Process(target=function, args=(string,))
    p.start()
    p.join()
