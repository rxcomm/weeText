#!/usr/bin/env python

import sys
import cPickle
import time
import re
import os
import glob
from googlevoice import Voice
from googlevoice.util import input
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
            phone = tree_inp.find('input', "gc-quickcall-ac")['value']

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
        print cPickle.dumps(convos)+'#####'

if __name__ == '__main__':
    # create voice instance
    email = sys.argv[1]
    passwd = sys.argv[2]

    time.sleep(float(sys.argv[3]))

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
