#!/usr/bin/env python
import os
import sys

from scapy.all import *

def exit_if_user_run_this_script_as_general_user():
    if not os.getuid() == 0:
        print 'Error: You need root permission to run this script.'
        sys.exit(os.EX_NOPERM)

def sniff_found_dash_button(packet):
    arp_packet = packet[ARP]
    print 'Please push dash button'

    if arp_packet.op == 1:
        if arp_packet.hwdst == '00:00:00:00:00:00':
            print 'Dash button found!'
            print 'MAC Address of Dash button:' + arp_packet.hwsrc
            sys.exit(0)

def found_dash_button():
    print sniff(prn=sniff_found_dash_button, filter="arp", store=0, count=10)

if __name__ == '__main__':
    exit_if_user_run_this_script_as_general_user()
