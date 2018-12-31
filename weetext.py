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

from googlevoice import Voice
from BeautifulSoup import BeautifulSoup, BeautifulStoneSoup, SoupStrainer

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
    def __init__(self, conv_id, number, messages):
        self.conv_id = conv_id
        self.number = number
        self.messages = messages

    def new_messages(self, other):
        assert len(self.messages) <= len(other.messages)
        return other.messages[len(self.messages):]

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
           #weechat.prnt('', 'getting more data')
            return weechat.WEECHAT_RC_OK
    if err != "":
        weechat.prnt("", "stderr: %s" % err)
        return weechat.WEECHAT_RC_OK

    try:
        conversations = reversed(cPickle.loads(conv))
    except EOFError:
        weechat.prnt('', 'wtrecv returned garbage')
        return weechat.WEECHAT_RC_OK

    for conversation in conversations:
        if not conversation.conv_id in conversation_map:
            conversation_map[conversation.conv_id] = conversation
            msgs = conversation.messages
        else:
            old = conversation_map[conversation.conv_id]
            conversation_map[conversation.conv_id] = conversation
            msgs = old.new_messages(conversation)
        for msg in msgs:
            if not conversation.number in number_map and msg['from'] != 'Me:':
                number_map[conversation.number] = msg['from']
        for msg in msgs:
            if conversation.number in number_map:
                buf = weechat.buffer_search('python', number_map[conversation.number][:-1])
                if not buf:
                    buf = weechat.buffer_new(number_map[conversation.number][:-1],
                                             "textOut", "", "buffer_close_cb", "")
            else:
                buf = weechat.buffer_search('python', 'Me')
                if not buf:
                    buf = weechat.buffer_new('Me', "textOut", "", "buffer_close_cb", "")
            if weechat.config_get_plugin('encrypt_sms') == 'True':
                msg['text'] = decrypt(msg['text'], buf)
            nick = msg['from'][:-1].strip()
            tags = 'notify_private,nick_' + msg['from'][:-1].strip()
            tags += ',log1,prefix_nick_' + weechat.info_get('irc_nick_color_name', nick)
            nick = msg['from'][:-1].strip()

            if "Group Message" in conversation.number and nick != "Me":
                try:
                    unknown_num, msg_txt = msg['text'].split("-", 1)
                except ValueError:
                    pass
                else:
                    real_name = number_map.get(unknown_num.strip())
                    if real_name:
                        msg['text'] = "{} {}".format(real_name, msg_txt)

            weechat.prnt_date_tags(buf, 0, tags, '\x03' + weechat.info_get('irc_nick_color', nick)
                                   + nick + '\t' + msg['text'])
    conv = ''
    callGV()
    return weechat.WEECHAT_RC_OK

def textOut(data, buf, input_data):
    global number_map
    number = None
    for num, dest in number_map.iteritems():
        if dest[:-1] == weechat.buffer_get_string(buf, 'name'):
            if "Group Message" not in num:
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
        proc_data = email + '\n' + passwd + '\n' + number + '\n' +\
                    input_data + '\n' + msg_id + '\n' + api_key + '\n'
        weechat.hook_set(send_hook, 'stdin', proc_data)
    else:
        proc_data = email + '\n' + passwd + '\n' +\
                    weechat.config_get_plugin('poll_interval') + '\n'
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
import time
import re
import os
import glob
from googlevoice import Voice
from BeautifulSoup import BeautifulSoup, BeautifulStoneSoup, SoupStrainer

user_path = os.path.expanduser('~')

class Conversation(object):
    def __init__(self, conv_id, number, messages):
        self.conv_id = conv_id
        self.number = number
        self.messages = messages

    def new_messages(self, other):
        assert len(self.messages) <= len(other.messages)
        return other.messages[len(self.messages):]

    def __iter__(self):
        return iter(reversed(self.messages))

class SMS:

    def getsms(self):
        # We could call voice.sms() directly, but I found this does a rather
        # inefficient parse of things which pegs a CPU core and takes ~50 CPU
        # seconds, while this takes no time at all.
        data = voice.sms.datafunc()
        data = re.search(r'<html><\!\[CDATA\[([^\]]*)', data, re.DOTALL).groups()[0]

        divs = SoupStrainer(['div', 'input'])
        tree = BeautifulSoup(data, parseOnlyThese=divs)

        convos = []
        conversations = tree.findAll("div", attrs={"id" : True},recursive=False)
        for conversation in conversations:
            inputs = SoupStrainer('input')
            tree_inp = BeautifulSoup(str(conversation),parseOnlyThese=inputs)
            tree_query = tree_inp.find('input', "gc-quickcall-ac")

            if tree_query:
                phone = tree_query['value']
                smses = []
                msgs = conversation.findAll(attrs={"class" : "gc-message-sms-row"})
                for row in msgs:
                    msgitem = {"id" : conversation["id"]}
                    spans = row.findAll("span", attrs={"class" : True}, recursive=False)
                    for span in spans:
                        cl = span["class"].replace('gc-message-sms-', '')
                        msgitem[cl] = (" ".join(span.findAll(text=True))).strip()
                    if msgitem["text"]:
                        msgitem["text"] = BeautifulStoneSoup(msgitem["text"],
                                          convertEntities=BeautifulStoneSoup.HTML_ENTITIES
                                          ).contents[0]
                        msgitem['phone'] = phone
                        smses.append(msgitem)
                convos.append(Conversation(conversation['id'], phone, smses))
        print cPickle.dumps(convos)

if __name__ == '__main__':

    email = sys.stdin.readline().strip()
    passwd = sys.stdin.readline().strip()
    poll_interval = sys.stdin.readline().strip()

    time.sleep(float(poll_interval))

    # create voice instance if no texts are being sent
    while True:
        f = glob.glob(user_path + '/.weechat/.gvlock*')
        if f == []:
            voice = Voice()
            voice.login(email=email, passwd=passwd)
            sms = SMS()
            sms.getsms()
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
    # This is a bare absolute minimal attempt at reverse engineering
    # a small portion of the new google voice API so that one could effectively
    # respond to sms messages with this plugin

    # This is bad, but it gets the job done. This google voice module
    # currently does not support group text messages and even some
    # normal messages. This at least enables this plugin to use the
    # modern google voice API for sending SMS. Receiving is a major TODO still
    # and relies on the current existing implementation in ```getsms```

    # In order to extract the headers, I messed around with the HTTP archive coming
    # out of firefox and made various combinations of headers until I got this working

    # The body hack is just luck.
    # * Index 4: The message body
    # * Index 5: The number identifier
    # * Index 6: Used for new numbers (does not have group or text prefix)

    # The last index of the body is magic to me, I have no idea what it is. I could
    # not send out group sms until I wiped out that element. It was a random guess that
    # just happened to work. Without wiping it out, a successful response is still
    # returned but the message does not send

    # An update needs to be made to the google voice package to wrap
    # around the new api

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
            raise Exception(res.text)

try:
    voice = Voice()
    voice.login(email, passwd)
    if api_key:
        send_sms(voice.session, number, payload)
    else:
        voice.send_sms(number, payload)
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
