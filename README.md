bwlogtools
==========

bwxslogtool.py -- This tool parses sip messages out of the broadworks App Server's XS log

USAGE
=====

```
usage: bwxslogtool.py [-h] [-p FILENAME] [-m REGEX] [--bwip BWIP] XSLog

currently this tool prints sip logs to STDOUT that match the
pattern defined in the -m option, or if -p is specified it will print the sip
messages to the specified pcap file

positional arguments:
  XSLog                 XSLog to parse

optional arguments:
  -h, --help            show this help message and exit
  -p FILENAME, --pcap FILENAME
                        PCAP file to write logs to.
  -m REGEX, --match REGEX
                        Pattern to match
  --bwip BWIP           ip address of the broadworks server to be used when
                        writing to pcap files
```

Without the -p flag the script simply prints the sip messages to the terminal, and you can use the -m flag to search for specific messages, something like the following would print all SIP INVITE messages in the given file:

```
./bwxslogtool.py -m "^INVITE" XSLogFile
```
Then if you wanted to see a call with a specific call-id you would do something like the following:
```
./bwxslogtool.py -m "<YOUR_CALL_ID_HERE>" XSLogFile
```
Basically the -m flag takes either text and searches for sip messages containing that text, or for advanced users you can use regular expressions.

The -p flag followed by a filename will cause the script to write all sip messages to the filename in libpcap format so that you can analyze the logs using wireshark, snoop, tcpdump or your favorite pcap analyzer ;-). 

I added the '--bwip' option because the logs don't contain the IP address of the broadworks server that is sending/receiving  the SIP messages.  If you want the PCAP to reflect the appropriate broadworks server, then use this flag

The following is an example of usage:

```
./bwxslogtool.py -p out.pcap --bwip 10.10.10.1 XSLogFileName
```
The above command would write all of the SIP messages in the log specified by the XSLogFileName to the file 'out.pcap', and would use 10.10.10.1 as the IP address of the broadworks server for the PCAP.

 


NOTES
=====
My testing was done with python 2.7... I got enough people complaining about issues with python 2.4 that I went ahead and made some major changes to ensure backwards compatibility (Including rolling my own PCAP writing code to avoid libraries that aren't included in the stdlib). 


This has been tested on various flavors of linux (Redhat, Ubuntu, SUSE) as well as OSX.  I have not tested on windows, but welcome any feedback.
Unfortunately I had to use a third party library that is not included in the python standard library (scapy) so that will need to be included. I will be maintaining this and adding any features that folks find useful, please report any bugs on github. 

I only have broadworks 17sp3 in the lab so that is all I tested this on, but I know that the log format hasn't changed in a while.  If someone sends me logs from R18 or R19 i'd be more than happy to test, or you can ;-)

Please file bugs on github as you find them, and I will fix!
