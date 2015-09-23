set1.pcap

1. How many packets are there in this set? 
861

2. What protocol was used to transfer files from PC to server?
FTP

3. Briefly describe why the protocol used to transfer the files is insecure?
It sends credentials in plain text to the server, and all the files that you exchange with the server are also transferred in plain text, without any encryption.

4. What is the secure alternative to the protocol used to transfer files?
SFTP

5. What is the IP address of the server?
192.168.1.8

6. What was the username and password used to access the server?
USER: defcon PASS: m1ngisablowhard

7. How many files were transferred from PC to server?
6 files

8. What are the names of the files transferred from PC to server?
CDkv69qUsAAq8zN.jpg
CJoWmoOUkAAAYpx.jpg
CKBXgmOWcAAtc4u.jpg
CLu-m0MWoAAgjkr.jpg
CNsAEaYUYAARuaj.jpg
COaqQWnU8AAwX3K.jpg

9. Extract all the files that were transferred from PC to server. These files must be part of your submission!

set2.pcap

10. How many packets are there in this set?
77982

11. How many plaintext username-password pairs are there in this packet set? Please count any anonymous or generic accounts.
I was only able to find one plaintext username-password pair. 
USER: "larry@radsot.com"  PASS: "Z3lenzmej"
I'm not sure if they count as "generic" logins, but connections to the defcon open wifi using DHCP occurred multiple times, and SNMP was used: COMMUNITY: public  INFO: SNMP v1. 
I also found an authorizableId: anonymous for *.splunk.com. 

12. Briefly describe how you found the username-password pairs.
I used: ettercap -T -r set2.pcap | grep -i "PASS"
In addition to grepping for PASS, I grepped for "LOGIN", "USER", "UNAME", "PW", "GENERIC", and "ANON".

13. For each of the plaintext username-password pair that you found, identify the protocol used, server IP, the corresponding domain name (e.g., google.com), and port number.
protocol: IMAP
server IP: 87.120.13.118
domain name: d6.net
port number: 143

IMPORTANT NOTE: PLEASE DO NOT LOG ON TO THE WEBSITE OR SERVICE ASSOCIATED WITH THE USERNAME-PASSWORD THAT YOU FOUND!

14. Of all the plaintext username-password pairs that you found, how many of them are legitimate? That is, the username-password was valid, access successfully granted? Please do not count any anonymous or generic accounts.
larry@radsot.com:Z3lenzmej is a legitimate username-password pair.

set3.pcap

15. How many plaintext username-password pairs are there in this packet set? Please count any anonymous or generic accounts.
I found three plaintext username-password pairs in this packet set. 
USER: nab01620@nifty.com  PASS: Nifty->takirin1
USER: jeff  PASS: asdasdasd
USER: seymore  PASS: butts

For generic/anonymous accounts, again, there were plenty of logins into the open defcon wifi on DHCP. Additionally, I found:
COMMUNITY: public  INFO: SNMP v1

16. For each of the plaintext username-password pair that you found, identify the protocol used, server IP, the corresponding domain name (e.g., google.com), and port number.
nab01620@nifty.com:Nifty->takirin1
Protocol: IMAP
Server IP: 210.131.4.155
Domain Name: nifty.ad.jp 
Port: 143

jeff:asdasdasd (NOTE: ettercap showed this as plaintext, but the communication used HTTP basic auth, which does use Base64, so username & password are transmitted as amVmZjphc2Rhc2Rhc2Q=)
Protocol: HTTP
Server IP: 54.191.109.23
Domain Name: ec2.intelctf.com
Port: 80

seymore:butts
Protocol: HTTP
Server IP: 162.222.171.208
Domain Name: forum.defcon.org
Port: 80

IMPORTANT NOTE: PLEASE DO NOT LOG ON TO THE WEBSITE OR SERVICE ASSOCIATED WITH THE USERNAME-PASSWORD THAT YOU FOUND!

17. Of all the plaintext username-password pairs that you found, how many of them are legitimate? That is, the username-password was valid, access successfully granted? Please do not count any anonymous or generic accounts.
Two are legitimate:
1) nab01620@nifty.com:Nifty->takirin1
2) jef:asdasdasd 

18. Provide a listing of all IP addresses with corresponding hosts (hostname + domain name) that are in this PCAP set. Describe your methodology.

General Questions

19. How did you verify the successful username-password pairs?
I used Wireshark to follow the TCP stream, and I was able to see whether the logins succeeded or failed based on subsequent activity. (Login OK, or HTTP/1.1 403 Forbidden, or HTTP/1.1 200 OK)

20. What advice would you give to the owners of the username-password pairs that you found so their account information would not be revealed "in-the-clear" in the future?
1) Don't use shared/public or unencrypted networks
2) If you have to do (1), don't login to sites with insecure protocols such as HTTP, FTP, and IMAP. 
3) Don't use the wifi at defcon.


