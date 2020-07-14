#Possible Hash - in Kali
```
hash-identifier

> <hash>
```
#with John
```
john --rules --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```
  
  
  

we have to crack the idrsa

  
```
1. ./ssh2john.py id_rsa > id_rsa.crack

2. john id_rsa.crack --wordlist=/usr/share/wordlists/rockyou.txt
```
   

#with Hashcat
```
hashcat -m <mode-a 0 hash.txt /usr/share/wordlists/rockyou.txt --force

hashcat64.exe -m <mode> file.hash rockyou.txt`
```
  
  

# KDBX

```
1. keepass2john CEH.kdbx

2. hashcat -m 13400 file.keepass rockyou.txt
```
  
  

#with Online
```
https://crackstation.net/

```  
  

# password crack with GPP

  

```
python3 gpp-decrypt.py -f Groups.xml
```

  
  

# Haydra

  

1. On HTTP

  
```
hydra -l <user> -P /usr/share/wordlists/metasploit/common_roots.txt 127.0.0.1 http-form-post "/simple_chat/login_form.php:uname=^USER^&passwd=^PASS^&submit=Login:Password"
```
  

2. will use Hydra to find apache manager cred

  
```
hydra -C /usr/share/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt -s 8080 <ip> http-get /manager/html

hydra -l admin -P /usr/share/wordlists/SecLists/Passwords/Common-Credentials/10k-most-common.txt <ip> http-post-form "/department/login.php:username=^USER^&password=^PASS^:Invalid" -t 64

hydra -l admin -P /usr/share/wordlists/SecLists/Passwords/Common-Credentials/10k-most-common.txt <ip> http-post-form "/db/index.phppassword=^PASS^&login=Log+In&proc_login=true:Incorrect" -t 64
```

##  "bruteforce -salted ssl" , with default digest as sha256 (openssl defalt digest is sha256)

  
  

```bash
bruteforce-salted-openssl -t 10 -d sha256 -f /usr/share/wordlists/rockyou.txt -c aes-256-cbc drupal.enc.decoded
```
```
openssl aes-256-cbc -d -in drupal.enc.decoded -out drupal.txt -k friends
```

  
  



