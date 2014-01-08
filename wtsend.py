#!/usr/bin/env python

import sys
import os
from googlevoice import Voice
from googlevoice.util import input

user_path = os.path.expanduser('~')
email = sys.argv[1]
passwd = sys.argv[2]
number = sys.argv[3]
payload = sys.argv[4]
msg_id = sys.argv[5]

open(user_path + '/.weechat/.gvlock.' + msg_id, 'a').close()

try:
    voice = Voice()
    voice.login(email, passwd)
    voice.send_sms(number, payload)
    print '<message sent>'
except:
    print '<message NOT sent!>'

os.remove(user_path + '/.weechat/.gvlock.' + sys.argv[5])
