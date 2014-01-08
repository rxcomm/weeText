# ===============================================================
SCRIPT_NAME    = "weetext"
SCRIPT_AUTHOR  = "David R. Andersen <k0rx@RXcomm.net>, Tycho Andersen <tycho@tycho.ws>"
SCRIPT_VERSION = "0.0.2"
SCRIPT_LICENSE = "GPL3"
SCRIPT_DESC    = "SMS Text Messaging plugin for Weechat using Google Voice"

"""
This script implements chatting via text message with Weechat.

Email and password should be configured (either by editing the script
itself or adding options to plugins.conf). For using secure passwords, 
see the weechat /secure command.

The script will block weechat briefly at startup when it is logging in to
Google Voice. Also, at this time sendText is threaded, but recText is
not.

To initiate a text message session with someone new, type the command:

text <10 digit phone number>

This will pop open a new buffer.

I've also added optional encryption using ssl. This is essentially a wholesale
copy of the encrypt() and decrypt() methods from the weechat crypt.py script.
Thanks to the authors for that!

Todo:
1. non-blocking sms.getsms()

"""

import weechat
import sys
import os
import re
import cPickle
import subprocess
import random
import string
import threading
from googlevoice import Voice
from googlevoice.util import input
from BeautifulSoup import BeautifulSoup, BeautifulStoneSoup, SoupStrainer

script_options = {
    "email" : "", # GV email address
    "passwd" : "", # GV password - can use /secure
    "poll_interval" : "120", # poll interval for receiving messages (sec)
    "encrypt_sms" : "True",
    "key_dir" : "/cryptkey",
    "cipher" : "aes-256-cbc",
    "message_indicator" : "(enc) ",
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
            weechat.prnt('', 'getting more data')
            return weechat.WEECHAT_RC_OK
    if err != "":
        weechat.prnt("", "stderr: %s" % err)
        return weechat.WEECHAT_RC_OK

    conversations = reversed(cPickle.loads(conv))

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
            weechat.prnt(buf, msg['from'] + ' ' + msg['text'])
    conv = ''
    weechat.hook_process(weechat_dir + '/python/wtrecv.py ' + email + ' ' + passwd + ' ' +
                         weechat.config_get_plugin('poll_interval'), 0,
                         'renderConversations', '')
    return weechat.WEECHAT_RC_OK

def textOut(data, buf, input_data):
    global number_map
    number = None
    for num, dest in number_map.iteritems():
        if dest[:-1] == weechat.buffer_get_string(buf, 'name'):
            number = num[2:]
    if not number:
        number = weechat.buffer_get_string(buf, 'name')[2:]
    if weechat.config_get_plugin('encrypt_sms') == 'True':
        input_data = encrypt(input_data, buf)
    msg_id = ''.join(random.choice(string.lowercase) for x in range(4))
    weechat.hook_process(weechat_dir + '/python/wtsend.py ' + email + ' ' +
                         passwd + ' ' + number + ' "' + input_data + '" ' +
                         msg_id, 0, 'sentCB', weechat.buffer_get_string(buf, 'name'))
    return weechat.WEECHAT_RC_OK

def sentCB(buf_name, command, return_code, out, err):
    if return_code == weechat.WEECHAT_HOOK_PROCESS_ERROR:
        weechat.prnt("", "Error with command '%s'" % command)
        return weechat.WEECHAT_RC_OK
    if return_code >= 0:
        weechat.prnt("", "return_code = %d" % return_code)
    if out != "":
        weechat.prnt(weechat.buffer_search('python', buf_name), out)
    if err != "":
        weechat.prnt("", "stderr: %s" % err)
    return weechat.WEECHAT_RC_OK

def gvOut(data, buf, input_data):
    if input_data[:4] == 'text' and buf == weechat.buffer_search('python', 'weeText'):
        buffer = weechat.buffer_new("+1"+input_data[5:], "textOut", "", "buffer_close_cb", "")
    return weechat.WEECHAT_RC_OK

def buffer_input_cb(data, buf, input_data):
    # ...
    return weechat.WEECHAT_RC_OK

def buffer_close_cb(data, buf):
    return weechat.WEECHAT_RC_OK

def encrypt(message, buf):
  username=weechat.buffer_get_string(buf, 'name')
  if os.path.exists(weechat_dir + key_dir + "/cryptkey." + username):
    p = subprocess.Popen(["openssl", "enc", "-a", "-" + weechat.config_get_plugin("cipher"), "-pass" ,"file:" + weechat_dir + key_dir + "/cryptkey." + username], bufsize=4096, stdin=PIPE, stdout=PIPE, stderr=PIPE, close_fds=True)
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
    p = subprocess.Popen(["openssl", "enc", "-d", "-a", "-" + weechat.config_get_plugin("cipher"), "-pass" ,"file:" + weechat_dir + key_dir + "/cryptkey." + username], bufsize=4096, stdin=PIPE, stdout=PIPE, stderr=PIPE, close_fds=True)
    p.stdin.write("U2FsdGVkX1" + message.replace("|","\n"))
    p.stdin.close()
    decrypted = p.stdout.read()
    p.stdout.close()
    if decrypted == "":
      return message
    decrypted = ''.join(c for c in decrypted if ord(c) > 31 or ord(c) == 9 or ord(c) == 2 or ord(c) == 3 or ord(c) == 15)
    return weechat.config_get_plugin("message_indicator") + decrypted
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
    if re.search('sec.*data', passwd):
        passwd=weechat.string_eval_expression(passwd, {}, {}, {})

    # register the hooks
    weechat.hook_signal("buffer_switch","update_encryption_status","")
    weechat.hook_process(weechat_dir + '/python/wtrecv.py ' + email + ' ' + passwd + ' ' +
                         weechat.config_get_plugin('poll_interval'), 0,
                         'renderConversations', '')
