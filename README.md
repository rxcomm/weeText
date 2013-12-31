weeText
=======

Text messaging script for Weechat using Google Voice

=== Usage:

1) Edit the script or ```~/.weechat/plugins.conf``` and input
your credentials.

plugins.conf:

     python.weetext.email = "your_address@gmail.com"
     python.weetext.passwd = "${sec.data.weetext}"
     python.weetext.poll_interval = "2"

or, if you don't want to use the /secure password storage
in weechat:

     python.weetext.passwd = "mypasswd"

Load the script and weechat should connect to Google Voice.
Then after "polling_interval" seconds, you should see
all of your available text message conversations - one
buffer per phone number.

In the weetext window, you can open text message windows
to additional phone numbers by typing the command:

     text 0123456789

This will open a texting window to phone number 0123456789.

=== Todos:

1. threaded ```recText()``` and ```login()```

2. encrypted text messaging

Enjoy!
