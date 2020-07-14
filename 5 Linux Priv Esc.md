# LINUX

  

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

## For more of the manual enumeration steps;

https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
https://book.hacktricks.xyz/linux-unix/privilege-escalation

  
  
