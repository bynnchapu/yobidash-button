#!/usr/bin/env python
import os
import sys

from scapy.all import *

DASH_BUTTON_MAC_ADDR = 'SPECIFY MAC ADDR OF DASH BUTTON'

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


def sniff_handle_dash_button(packet):
    arp_packet = packet[ARP]

    if arp_packet.op == 1:
        if arp_packet.hwdst == '00:00:00:00:00:00':
            if arp_packet.hwsrc == DASH_BUTTON_MAC_ADDR:
                print 'Dash button is pusshed!'


def handle_dash_button():
    print sniff(prn=sniff_handle_dash_button, filter="arp", store=0, count=0)


if __name__ == '__main__':
    exit_if_user_run_this_script_as_general_user()
