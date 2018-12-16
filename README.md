weeText
=======

Text messaging script for Weechat using Google Voice

### Usage:

1) Edit the script or ```~/.weechat/plugins.conf``` and input
your credentials and desired poll interval.

plugins.conf:

     python.weetext.email = "your_address@gmail.com"
     python.weetext.passwd = "${sec.data.weetext}"
     python.weetext.poll_interval = "120"

or, if you don't want to use the /secure password storage
in weechat:

     python.weetext.passwd = "mypasswd"

Load the script and weechat should connect to Google Voice.
Then after "polling_interval" seconds, you should see
your available text message conversations - one buffer per
phone number contact.

In the weetext window, you can open text message windows
to additional phone numbers by typing the command (from the
weeText buffer):

     text 0123456789

This will open a texting window to phone number 0123456789.

You can also text multiple numbers at the same time. The syntax
for this is (in the weeText buffer):

     multi <number1>,<number2>,...

Finally, weeText incorporates the possibility of symmetric encryption
of text messages using OpenSSL. The code for this comes directly from
the crypt.py script, and you are encouraged to take a look at that
script for usage instructions. One small difference, the cryptkey.*
files are stored in ```%h/cryptkey``` rather than in ```%h``` as is
the case for the crypt.py script

### pygooglevoice Dependency

This module is synchronized to work with the latest ```googlevoice``` package
which can be retrieved via:

```bash
pip install googlevoice
```


### Todos:

1. right now there aren't really any... ```;-)```

Enjoy!
