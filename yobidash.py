#!/usr/bin/env python
import os
import sys
import slackweb
import pygame.mixer
import argparse

from scapy.all import *

DASH_BUTTON_MAC_ADDR = 'SPECIFY MAC ADDR OF DASH BUTTON'
SLACK_WEB_HOOK_URL = 'SPECIFY YOUR SLACK WEB HOOK URL'
SLACK_MESSAGE = 'Dash button is pusshed!'
SOUND_PATH = './config/sound.mp3'

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


def post_slack_notify():
    slack = slackweb.Slack(SLACK_WEB_HOOK_URL)
    slack.notify(text=SLACK_MESSAGE)


def play_bell():
    pygame.mixer.init()
    pygame.mixer.music.load(SOUND_PATH)
    pygame.mixer.music.play(1)


def sniff_handle_dash_button(packet):
    arp_packet = packet[ARP]

    if arp_packet.op == 1:
        if arp_packet.hwdst == '00:00:00:00:00:00':
            if arp_packet.hwsrc == DASH_BUTTON_MAC_ADDR:
                print 'Dash button is pusshed!'
                post_slack_notify()
                play_bell()


def handle_dash_button():
    print sniff(prn=sniff_handle_dash_button, filter="arp", store=0, count=0)


def parse_arguments():
    parser = argparse.ArgumentParser(description='Yobidash Button')

    parser.add_argument('--find-dash', action='store_true',
                        help='Found MAC address of Dash Button.')
    parser.add_argument('--mac-addr', type=str,
                        help='Specify MAC Address of Dash Button.')
    parser.add_argument('--slack-web-hook-url', type=str,
                        help='Specify URL for slack web hook')
    parser.add_argument('--slack-message', type=str,
                        help='Specify message for slack')
    parser.add_argument('--sound-path', type=str,
                        help='Specify path for bell sound')
    parser.add_argument('--disable-slack', action='store_true',
                        help='Disable posting to slack.')
    parser.add_argument('--disable-sound', action='store_true',
                        help='Disable play sound.')

    return parser.parse_args()


def set_behavior_variable(args):
    global DISABLE_SLACK
    global DISABLE_SOUND
    global DASH_BUTTON_MAC_ADDR
    global SLACK_WEB_HOOK_URL
    global SLACK_MESSAGE
    global SOUND_PATH

    if args.disable_slack:
        DISABLE_SLACK = True
    else:
        DISABLE_SLACK = False

    if args.disable_sound:
        DISABLE_SOUND = True
    else:
        DISABLE_SOUND = False

    if args.mac_addr:
        DASH_BUTTON_MAC_ADDR = args.mac_addr

    if args.slack_web_hook_url:
        SLACK_WEB_HOOK_URL = args.slack_web_hook_url

    if args.slack_message:
        SLACK_MESSAGE = args.slack_mesasge

    if args.sound_path:
        SOUND_PATH = args.sound_path


if __name__ == '__main__':
    exit_if_user_run_this_script_as_general_user()
    args = parse_arguments()
    set_behavior_variable(args)

    if args.find_dash:
        found_dash_button()
    else:
        handle_dash_button()
