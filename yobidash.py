#!/usr/bin/env python
import os
import sys

def exit_if_user_run_this_script_as_general_user():
    if not os.getuid() == 0:
        print 'Error: You need root permission to run this script.'
        sys.exit(os.EX_NOPERM)

if __name__ == '__main__':
    exit_if_user_run_this_script_as_general_user()
