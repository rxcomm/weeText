
# ===============================================================

# Copyright (C) 2014 by David R. Andersen and Tycho Andersen

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Development repository at: https://github.com/rxcomm/weeText/

SCRIPT_NAME    = "weetext"
SCRIPT_AUTHOR  = "David R. Andersen <k0rx@RXcomm.net>, Tycho Andersen <tycho@tycho.ws>"
SCRIPT_VERSION = "0.1.2"
SCRIPT_LICENSE = "GPL3"
SCRIPT_DESC    = "SMS Text Messaging script for Weechat using Google Voice"

"""
This script implements chatting via text message with Weechat.

Email and password should be configured (either by editing the script
itself before loading or adding options to plugins.conf). For using
secure passwords, see the weechat /secure command.

To initiate a text message session with someone new, that isn't currently
in your weeText buffer list, in the weeText buffer type the command:

text <10 digit phone number>

This will pop open a new buffer.

You can also send text messages to multiple numbers. The syntax is (from
the weeText buffer):

multi <number1>,<number2>,...

This will pop open a new multi-text buffer.

I've also added optional symmetric-key encryption using OpenSSL. This is
essentially a wholesale copy of the encrypt() and decrypt() methods from
the weechat crypt.py script. Thanks to the authors for that!

You need _at least_ the following modules in order for weeText to run:
     beautifulsoup
     pygooglevoice

Todo:
1. Add buffer for texting multiple parties at the same time.

"""

import weechat
import sys
import os
import glob
import re
import cPickle
import subprocess
import random
import string

from collections import OrderedDict

from googlevoice import Voice

script_options = {
    "email" : "", # GV email address
    "passwd" : "", # GV password - can use /secure
    "poll_interval" : "120", # poll interval for receiving messages (sec)
    "encrypt_sms" : "True",
    "key_dir" : "/cryptkey",
    "cipher" : "aes-256-cbc",
    "message_indicator" : "(enc) ",
    "api_key" : "" # google voice api key. TODO find dynamically?
}

conversation_map = {}
number_map = {}
conv = ''

class Conversation(object):
    def __init__(self, number, messages):
        self.number = number
        self.__messages = OrderedDict([(msg["msg_id"], msg) for msg in messages])

    @property
    def messages(self):
        return self.__messages.values()

    def __len__(self):
        return len(self.messages)

    def new_messages(self, other):
        new_msg_ids = set(other.__messages.keys()) - set(self.__messages.keys())
        return [other.__messages[k] for  k in new_msg_ids]

    def __iter__(self):
        return iter(reversed(self.messages))

def renderConversations(unused, command, return_code, out, err):
    global conversation_map
    global conv

    if return_code == weechat.WEECHAT_HOOK_PROCESS_ERROR:
        weechat.prnt("", "Error with command '%s'" % command)
        return weechat.WEECHAT_RC_OK
    if return_code > 0:
        weechat.prnt("", "return_code = %d" % return_code)
    if out != '':
        conv += out
        if return_code == weechat.WEECHAT_HOOK_PROCESS_RUNNING:
            return weechat.WEECHAT_RC_OK
    if err != "":
        weechat.prnt("", "stderr: %s" % err)
        return weechat.WEECHAT_RC_OK

    try:
        conversations = [
            Conversation(*args) for args in reversed(cPickle.loads(conv))
        ]
    except EOFError:
        weechat.prnt('', 'wtrecv returned garbage')
        return weechat.WEECHAT_RC_OK

    for conversation in conversations:
        if conversation.number not in conversation_map:
            conversation_map[conversation.number] = conversation
            msgs = conversation.messages
        else:
            old = conversation_map[conversation.number]
            conversation_map[conversation.number] = conversation
            msgs = old.new_messages(conversation)
        for msg in msgs:
            if conversation.number not in number_map and msg['from'] != 'Me':
                if conversation.number.startswith("Group Message"):
                    number_map[conversation.number] = conversation.number
                else:
                    number_map[conversation.number] = msg['from']

        for msg in msgs:
            if conversation.number in number_map:
                buf = weechat.buffer_search('python', number_map[conversation.number])
                if not buf:
                    buf = weechat.buffer_new(number_map[conversation.number],
                                             "textOut", "", "buffer_close_cb", "")
            else:
                buf = weechat.buffer_search('python', 'Me')
                if not buf:
                    buf = weechat.buffer_new('Me', "textOut", "", "buffer_close_cb", "")
            if weechat.config_get_plugin('encrypt_sms') == 'True':
                msg['text'] = decrypt(msg['text'], buf)
            nick = msg['from'].strip()
            tags = ('notify_private,nick_' +
                    nick +
                    ',log1,prefix_nick_' +
                    weechat.info_get('irc_nick_color_name', nick))

            weechat.prnt_date_tags(buf, 0, tags, '\x03' + weechat.info_get('irc_nick_color', nick)
                                   + nick + '\t' + msg['text'])
    conv = ''
    callGV()
    return weechat.WEECHAT_RC_OK

def textOut(data, buf, input_data):
    global number_map
    number = None
    for num, dest in number_map.iteritems():
        if dest == weechat.buffer_get_string(buf, 'name'):
            if not num.startswith("Group Message"):
                number = num[2:]
            else:
                number = num
    if not number:
        number = weechat.buffer_get_string(buf, 'name')[2:]
    if weechat.config_get_plugin('encrypt_sms') == 'True':
        input_data = encrypt(input_data, buf)
    msg_id = ''.join(random.choice(string.lowercase) for x in range(4))
    callGV(buf=buf, number=number, input_data=input_data, msg_id=msg_id, send=True)
    return weechat.WEECHAT_RC_OK

def multiText(data, buf, input_data):
    global number_map
    numbers = data.split(',')
    if weechat.config_get_plugin('encrypt_sms') == 'True':
        input_data = encrypt(input_data, buf)
    for number in numbers:
        msg_id = ''.join(random.choice(string.lowercase) for x in range(4))
        callGV(buf=buf, number=number, input_data=input_data, msg_id=msg_id, send=True)
    return weechat.WEECHAT_RC_OK

def sentCB(buf_name, command, return_code, out, err):
    if return_code == weechat.WEECHAT_HOOK_PROCESS_ERROR:
        weechat.prnt("", "Error with command '%s'" % command)
        return weechat.WEECHAT_RC_OK
    if return_code > 0:
        weechat.prnt("", "return_code = %d" % return_code)
    if out != "":
        tags = 'notify_message'
        weechat.prnt_date_tags(weechat.buffer_search('python', buf_name), 0, tags, out)
    if err != "":
        weechat.prnt("", "stderr: %s" % err)
    return weechat.WEECHAT_RC_OK

def gvOut(data, buf, input_data):
    if input_data[:4] == 'text' and buf == weechat.buffer_search('python', 'weeText'):
        buffer = weechat.buffer_new("+1"+input_data[5:], "textOut", "", "buffer_close_cb", "")
    if input_data[:5] == 'multi' and buf == weechat.buffer_search('python', 'weeText'):
        num_list = input_data[6:].split(',')
        nums = ''
        for num in num_list:
            nums += '+' + num[-4:]
        nums = nums[1:]
        buffer = weechat.buffer_new('m:' + nums, "multiText", input_data[6:], "buffer_close_cb", "")
    return weechat.WEECHAT_RC_OK

def buffer_input_cb(data, buf, input_data):
    # ...
    return weechat.WEECHAT_RC_OK

def buffer_close_cb(data, buf):
    return weechat.WEECHAT_RC_OK

def encrypt(message, buf):
  username=weechat.buffer_get_string(buf, 'name')
  if os.path.exists(weechat_dir + key_dir + "/cryptkey." + username):
    p = subprocess.Popen(["openssl", "enc", "-a", "-" + weechat.config_get_plugin("cipher"),
                          "-pass" ,"file:" + weechat_dir + key_dir + "/cryptkey." + username],
                          bufsize=4096, stdin=PIPE, stdout=PIPE, stderr=PIPE, close_fds=True)
    p.stdin.write(message)
    p.stdin.close()
    encrypted = p.stdout.read()
    p.stdout.close()
    encrypted = encrypted.replace("\n","|")
    return encrypted[10:]
  else:
    return message

def decrypt(message, buf):
  username=weechat.buffer_get_string(buf, 'name')
  if os.path.exists(weechat_dir + key_dir + "/cryptkey." + username):
    p = subprocess.Popen(["openssl", "enc", "-d", "-a", "-" + weechat.config_get_plugin("cipher"),
                          "-pass" ,"file:" + weechat_dir + key_dir + "/cryptkey." + username],
                          bufsize=4096, stdin=PIPE, stdout=PIPE, stderr=PIPE, close_fds=True)
    p.stdin.write("U2FsdGVkX1" + message.replace("|","\n"))
    p.stdin.close()
    decrypted = p.stdout.read()
    p.stdout.close()
    if decrypted == "":
      return message
    decrypted = ''.join(c for c in decrypted if ord(c) > 31 or ord(c) == 9 or ord(c) == 2
                or ord(c) == 3 or ord(c) == 15)
    return '\x19' + weechat.color('lightred') + weechat.config_get_plugin("message_indicator") + '\x1C' + decrypted
  else:
    return message

def update_encryption_status(data, signal, signal_data):
    buffer = signal_data
    weechat.bar_item_update('encryption')
    return weechat.WEECHAT_RC_OK

def encryption_statusbar(data, item, window):
    if window:
      buf = weechat.window_get_pointer(window, 'buffer')
    else:
      buf = weechat.current_buffer()
    if os.path.exists(weechat_dir + key_dir + "/cryptkey." + weechat.buffer_get_string(buf, "short_name")):
      return weechat.config_get_plugin("statusbar_indicator")
    else:
      return ""

def checkWTrecv(*args):
    tmp = os.popen('ps -Af').read()
    if not tmp.count('wtrecv'):
        callGV()
    return weechat.WEECHAT_RC_OK


def callGV(buf=None, number=None, input_data=None, msg_id=None, send=False):
    if send:
        send_hook = weechat.hook_process_hashtable(weechat_dir + '/python/wtsend.py',
                    { 'stdin': '' }, 0, 'sentCB', weechat.buffer_get_string(buf, 'name'))
        proc_data_fmt_str = (
            "{email}{sep}{passwd}{sep}{number}{sep}"
            "{input_data}{sep}{msg_id}{sep}{api_key}{sep}"
        )

        proc_data = proc_data_fmt_str.format(
            email=email,
            passwd=passwd,
            number=number,
            input_data=input_data,
            msg_id=msg_id,
            api_key=api_key,
            sep="\n")
        weechat.hook_set(send_hook, 'stdin', proc_data)
    else:
        proc_data_fmt_str = (
            "{email}{sep}{passwd}{sep}{api_key}{sep}{poll_interval}{sep}"
        )
        proc_data = proc_data_fmt_str.format(
            email=email,
            passwd=passwd,
            api_key=api_key,
            poll_interval=weechat.config_get_plugin('poll_interval'),
            sep="\n")

        recv_hook = weechat.hook_process_hashtable(weechat_dir + '/python/wtrecv.py',
                { 'stdin': '' }, 0, 'renderConversations', '')
        weechat.hook_set(recv_hook, 'stdin', proc_data)

PIPE=-1

# register plugin
if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE, SCRIPT_DESC, "", "UTF-8"):
    buffer = weechat.buffer_new("weeText", "gvOut", "", "buffer_close_cb", "")
    weechat_dir = weechat.info_get("weechat_dir","")
    key_dir = weechat.config_get_plugin("key_dir")
    weechat.bar_item_new('encryption', 'encryption_statusbar', '')
    for option, default_value in script_options.iteritems():
        if not weechat.config_is_set_plugin(option):
            weechat.config_set_plugin(option, default_value)

    # get email/passwd and pass to other script
    email=weechat.config_get_plugin('email')
    passwd = weechat.config_get_plugin('passwd')
    api_key = weechat.config_get_plugin('api_key')
    if re.search('sec.*data', passwd):
        passwd=weechat.string_eval_expression(passwd, {}, {}, {})

    # write the helper files
    with open(weechat_dir + '/python/wtrecv.py', 'w') as f:
        f.write("""#!/usr/bin/env python2

import sys
import cPickle
import datetime
import time
import re
import os
import glob
from hashlib import sha1

from googlevoice import Voice

user_path = os.path.expanduser('~')

def get_sms():

    # TODO document  API response body in heavy detail
    # The body is not pretty and the indices of the important
    # parts need to be stored as constants and documented

    def build_headers(session):
        origin = "https://voice.google.com"
        date_utc = datetime.datetime.utcnow().strftime("%s")
        sapisid = session.cookies.get_dict()["SAPISID"]

        sapi_sid_hash = sha1(
            "{} {} {}".format(date_utc, sapisid, origin)
        ).hexdigest()

        headers = {
            'Authorization': 'SAPISIDHASH {}_{}'.format(date_utc, sapi_sid_hash),
            'Content-Type': 'application/json+protobuf',
            'X-JavaScript-User-Agent': 'google-api-javascript-client/1.1.0',
            'X-Origin': origin,
            'X-Referer': origin,
            'X-Requested-With': 'XMLHttpRequest'
        }
        return headers

    def build_req_body():
        # TODO this could be more customizeable
        # 10 and 25 are arbitrary numbers chosen here
        # The response comes back
        return [
            2, # gets messages (1) voicemail  (2) messages (3) unknown
            10, # number of threads
            25, # number of messages per thread to retrieve
            None, # unknown
            None, # unknown
            [None, None, None] # unknown
        ]

    def build_sms_url():
        url_tpl = "{url_base}/{endpoint}?{query_args}"

        if not api_key:
            raise ValueError("API key required")

        query_args = "protojson&key={}".format(api_key)

        url_base  = "https://clients6.google.com/voice/v1/voiceclient/api2thread"
        endpoint = "list"

        url = url_tpl.format(url_base=url_base,
                             endpoint=endpoint,
                             query_args=query_args)

        return url

    url = build_sms_url()

    headers = build_headers(voice.session)

    body = build_req_body()

    res = voice.session.post(url, headers=headers, json=body)

    if not res.ok:
        raise Exception(res.text)

    convos = []
    conversations = res.json()[0]

    msg_types = {"text": "t", "group_text": "g"}
    for conversation in conversations:
        smses = []
        msg_type, phone = conversation[0].split(".", 1) # <identifier>.<phone>
        msgs = conversation[2]

        name_number_map = {}
        if msg_type == msg_types["group_text"]:
            participants = msgs[0][14][3]

            for row in participants:
                human_name = row[0]
                number = row[1]
                name_number_map[number] = human_name

        for msg in reversed(msgs):
            msg_txt = msg[9].encode("ascii", "ignore") #TODO
            num = ""
            _from = ""
            try:
                num, _ = msg_txt.split(" - ", 1)
            except ValueError:
                pass
            finally:
                num = num.strip()
                _from = name_number_map.get(num)

                if not _from:
                    if  msg[-1] == 0: # not sent by me
                        _from = msg[3][0]
                    else:
                        _from = "Me"

            msg_id = msg[0]

            msg_item = {
                "text": msg_txt,
                "from": _from,
                "msg_id": msg_id,
                "phone": phone
            }
            smses.append(msg_item)
        convos.append((phone, smses))
    print cPickle.dumps(convos)

if __name__ == '__main__':

    email = sys.stdin.readline().strip()
    passwd = sys.stdin.readline().strip()
    api_key = sys.stdin.readline().strip()
    poll_interval = sys.stdin.readline().strip()

    time.sleep(float(poll_interval))

    # create voice instance if no texts are being sent
    while True:
        f = glob.glob(user_path + '/.weechat/.gvlock*')
        if f == []:
            voice = Voice()
            voice.login(email=email, passwd=passwd)
            get_sms()
            break
        else:
            time.sleep(1)
""")
    os.chmod(weechat_dir + '/python/wtrecv.py', 0755)

    with open(weechat_dir + '/python/wtsend.py', 'w') as f:
        f.write("""#!/usr/bin/env python2

import datetime
import os
import sys
from hashlib import sha1
from six.moves import input

from googlevoice import Voice

# read the credentials, payload, and msg_id from stdin
email = sys.stdin.readline().strip()
passwd = sys.stdin.readline().strip()
number = sys.stdin.readline().strip()
payload = sys.stdin.readline().strip()
msg_id = sys.stdin.readline().strip()
api_key = sys.stdin.readline().strip()

user_path = os.path.expanduser('~')
open(user_path + '/.weechat/.gvlock.' + msg_id, 'a').close()

def send_sms(session, number, payload):

    def build_headers(session):
        origin = "https://voice.google.com"
        date_utc = datetime.datetime.utcnow().strftime("%s")
        sapisid = session.cookies.get_dict()["SAPISID"]

        sapi_sid_hash = sha1(
            "{} {} {}".format(date_utc, sapisid, origin)
        ).hexdigest()

        headers = {
            'Authorization': 'SAPISIDHASH {}_{}'.format(date_utc, sapi_sid_hash),
            'Content-Type': 'application/json+protobuf',
            'X-JavaScript-User-Agent': 'google-api-javascript-client/1.1.0',
            'X-Origin': origin,
            'X-Referer': origin,
            'X-Requested-With': 'XMLHttpRequest'
        }
        return headers

    def build_sms_url():
        url_tpl = "{url_base}/{endpoint}?{query_args}"

        url_base  = "https://clients6.google.com/voice/v1/voiceclient/api2thread"

        endpoint = "sendsms"

        if not api_key:
            raise ValueError("API key required")

        query_args = "protojson&key={}".format(api_key)

        url = url_tpl.format(url_base=url_base,
                             endpoint=endpoint,
                             query_args=query_args)

        return url

    def build_request_body(payload, number, new_number=False):
        body = [
            None,
            None,
            None,
            None,
            '', # Message goes here
            '', # number identifier goes here (group message or single number)
            [], # new comma delimited numbers go here
            None,
            []
        ]

        body[4] = payload
        msg_type = "t" if "Group Message" not in number else "g"

        if msg_type == "t":
            # this weechat plugin strips this from the number
            # and this module itself has no reference to the buffer list
            number = "+1" + number

        if not new_number:
            body[5] = "{}.{}".format(msg_type, number)
        else:
            # new messages go into the 6th index and are comma separated numbers
            # This only supports one message at the time and this plugin
            # iterates over the numbers anyway
            body[6].append(number)
        return body


    headers = build_headers(session)
    url = build_sms_url()
    body = build_request_body(payload, number)

    res = session.post(url, headers=headers, json=body)
    if not res.ok:
        # might be a new phone number
        body = build_request_body(payload, number, new_number=True)
        res = session.post(url, headers=headers, json=body)
        if not res.ok:
            raise ValueError(res.text)

try:
    voice = Voice()
    voice.login(email, passwd)
    send_sms(voice.session, number, payload)
except Exception as exc:
    print '<message NOT sent!>: {}'.format(exc)
else:
    print '<message sent>'

os.remove(user_path + '/.weechat/.gvlock.' + msg_id)
""")
    os.chmod(weechat_dir + '/python/wtsend.py', 0755)

    # remove any old .gvlock.* files
    for gvlockfile in glob.glob(weechat_dir + '/.gvlock.*'):
        os.remove(gvlockfile)

    # register the hooks
    weechat.hook_signal("buffer_switch","update_encryption_status","")
    callGV()

    # make sure we are receiving data
    weechat.hook_timer(600000, 0, 0, 'checkWTrecv', '')
