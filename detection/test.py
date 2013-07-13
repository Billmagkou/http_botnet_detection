#!/usr/bin/env python

from scapy.all import *
import os
import re
from multi import *


#a=sniff(filter="(port 80 or 443) and host 192.168.1.76", iface="eth0", prn=lambda x:x.summary(), timeout=2)

def regexp(string):
    # pattern that matches exact ip addresses
#    pattern="\d*\.\d*\.\d*\.\d*"
    pattern="\d*\.{4}"
    regexp=re.compile(pattern)
    match=regexp.findall(string)
    return match


def find_linux_ip():
    """ Find ip of every interface except 'lo' to a linux pc """
    # executing ifconfig built in command
    out=subprocess.check_output(["sudo", "ifconfig"])
    # finding how many ip addresses exist
    num=out.count("inet addr")
    ip=[]
    for i in range(num):
        # finding position of ip addresses
        position=out.find("inet addr")
        # executing string that contains nth ip address (minimum 15 digits)
        string=out[position+10:position+25]
        # using regexp def to obtain exact ip occurance
        find=regexp(string)
        # appending to ip list
        ip.append(find[0])
        # decreasing out string's length
        out=out[position+25:]
    print ip
    return ip

def sniffer(ip):
    filter=[]
    for i in range(len(ip)):
        filter.append("host %s and (port 80 or port 443)" % ip[i])
    print filter[i]

    for i in range(len(ip)):
        skata(str(filter[i]))

a=find_linux_ip()
#sniffer(a)
