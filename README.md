weeText
=======

Text messaging script for Weechat using Google Voice

### Usage:

1) Edit the script or ```~/.weechat/plugins.conf``` and input
your credentials, api key and desired poll interval.

[Retrieving your modern google voice API key](#API-Key)

plugins.conf:

     python.weetext.email = "your_address@gmail.com"
     python.weetext.passwd = "${sec.data.weetext}"
     python.weetext.poll_interval = "120"
     python.weetext.api_key= "<api_key>"

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

It currently uses pygoogle voice to establish the login session

```bash
pip install googlevoice
```


### Todos:

1. Either: 
  A) remove pygooglevoice dependency as it is only used for login now 
  B) ideally, make necessary updates to pygoogle voice to wrap around new API

* Figure out how to retrieve API key automatically. 

### API-Key

The simplest way to retreive the api key is to open the developer tools in your favorite browser
and see the requests that it is sending when you are logged into google voice

The latest google voice regularly polls and there will be plenty of requests with the api key
in plain sight. See below examples:

The simplest way is to go to the developer tools in your browser and to see the requests
being sent. See screenshots below


#### Chromium 71.0.3578.98 Arch Linux
![chromium](https://user-images.githubusercontent.com/5562156/51813534-dec52400-2284-11e9-915e-913c2bd1c526.png)

#### Mozilla Firefox 64.0.2
![firefox](https://user-images.githubusercontent.com/5562156/51813542-e684c880-2284-11e9-95d2-c46e549f16a5.png)

Enjoy!
