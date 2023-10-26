# Splunk-2-Part-of-the-Blue-Primer-series
The following is the the Boss of the SOC from Try Hack Me 300 series questions

![image](https://github.com/Rory33160/Splunk-2-Part-of-the-Blue-Primer-series/assets/47018034/f06b1ed1-1c78-4f7d-ae4b-cdf33743501d)


Mallory's critical PowerPoint presentation on her MacBook gets encrypted by ransomware on August 18. What is the name of this file after it was encrypted?


To answer the first question we need to find the name of the computer and then the name of the file.

We start the search with  index="botsv2" *Mallory* 
From the search result of the previous search we see the host:
Host MACLORY-AIR13
![image](https://github.com/Rory33160/Splunk-2-Part-of-the-Blue-Primer-series/assets/47018034/fa7b6b67-a89f-4b67-87f1-2046779029e3)


According to the information given we know that the file is PowerPoint and has been encrypted
Building on what we gathered from the previous search and the file name we use the following    search to find  file.
index="botsv2" host="MACLORY-AIR13" (*.ppt OR *.pptx)


Here we see the encrypted file is Documents/Frothly_marketing_campaign_Q317.pptx.crypt



There is a Games of Thrones movie file that was encrypted as well. What season and episode is it? 

We had a few results so I excluded the ones that did not match what I was searching for.

![image](https://github.com/Rory33160/Splunk-2-Part-of-the-Blue-Primer-series/assets/47018034/a2acde8c-bb50-466a-ad98-ca73c998b189)

The field name column.target_path produce an answer. (This one might be tricky. The answer field on THM will only take the format s07e2

![image](https://github.com/Rory33160/Splunk-2-Part-of-the-Blue-Primer-series/assets/47018034/00abeb04-592a-4a69-a463-df17919ba871)

GoT.S7E2

The format that THM will take is s07e02

Kevin Lagerfield used a USB drive to move malware onto kutekitten, Mallory's personal MacBook. She ran the malware, which obfuscates itself during execution. Provide the vendor name of the USB drive Kevin likely used. Answer Guidance: Use time correlation to identify the USB drive.

What is given:
1.	index="botsv2" kutekitten  (kutekitten being the name of the Macbook)
Of course, the result is over 6000 events.

Other search combination that I tried included “ubs” and “mass storage”. Mass storage was a key word from the first search.

index="botsv2" kutekitten mass storage 
> index="botsv2" kutekitten mass storage source="/var/log/osquery/osqueryd.results.log"
Shows when the device was added and removed:


![image](https://github.com/Rory33160/Splunk-2-Part-of-the-Blue-Primer-series/assets/47018034/cdab3a4f-2d69-43e9-b195-e49ffdd85847)

Here we can see some vendor/manufacturer information.
Vendor ID , generic, serial and number are clues we can use to dig a little further

![image](https://github.com/Rory33160/Splunk-2-Part-of-the-Blue-Primer-series/assets/47018034/d43436a3-c6b6-4e8b-80e2-39657e0bca55)

Google search with the vendor id serial and model id brought us the answer.

![image](https://github.com/Rory33160/Splunk-2-Part-of-the-Blue-Primer-series/assets/47018034/6088978e-abb9-4b05-9e54-a01e6a3243c8)

What programming language is at least part of the malware from the question above written in?
Finding the language used in the malware
Still using index="botsv2" kutekitten
Added “columns.action”=CREATED

index="botsv2" kutekitten "columns.action"=CREATED
The result is the Md5 hash that we can look at in more detail on Virus Total

![image](https://github.com/Rory33160/Splunk-2-Part-of-the-Blue-Primer-series/assets/47018034/8e04cf2e-fb2a-41dc-9d2e-56aece2157f7)

The answer is Perl.


![image](https://github.com/Rory33160/Splunk-2-Part-of-the-Blue-Primer-series/assets/47018034/e37301d4-f07a-414c-ae8c-33dd57b49f54)


When was this malware first seen in the wild? Answer Guidance: YYYY-MM-DD
This is found under the details tab on Virus Total.

![image](https://github.com/Rory33160/Splunk-2-Part-of-the-Blue-Primer-series/assets/47018034/08f1240c-1284-4195-830d-22ce84f4e57e)

The malware infecting kutekitten uses dynamic DNS destinations to communicate with two C&C servers shortly after installation. What is the fully-qualified domain name (FQDN) of the first (alphabetically) of these destinations?

From the question above, what is the fully-qualified domain name (FQDN) of the second (alphabetically) contacted C&C server?
The FQDN on Virus Total under the relations tab.


![image](https://github.com/Rory33160/Splunk-2-Part-of-the-Blue-Primer-series/assets/47018034/9392a64b-5237-44c9-beaa-5f9f474d0c48)

Series 400

A Federal law enforcement agency reports that Taedonggang often spear phishes its victims with zip files that have to be opened with a password. What is the name of the attachment sent to Frothly by a malicious Taedonggang actor?

We know that the attachment is a zip file so we can include it the search. We also know this was likely delivered by email so we will use the stream email protocol with zip in the following search. 


 index="botsv2" sourcetype="stream:smtp"   "*.zip"


Base on the same search, we find the password 
="botsv2" sourcetype="stream:smtp"   "*.zip"

![image](https://github.com/Rory33160/Splunk-2-Part-of-the-Blue-Primer-series/assets/47018034/943be6cc-b418-42e0-ad9f-cf4ee023762c)

What is the password to open the zip file?

![image](https://github.com/Rory33160/Splunk-2-Part-of-the-Blue-Primer-series/assets/47018034/d98592eb-79c9-4163-89d6-846cc5fb1b6e)

The Taedonggang APT group encrypts most of their traffic with SSL. What is the "SSL Issuer" that they use for the majority of their traffic? Answer guidance: Copy the field exactly, including spaces.

Search used index="botsv2" sourcetype="stream:tcp" 45.77.65.211
SSl issuer

![image](https://github.com/Rory33160/Splunk-2-Part-of-the-Blue-Primer-series/assets/47018034/b735adac-cd4c-4c91-9ae2-a2e010814e41)

What unusual file (for an American company) does winsys32.dll cause to be downloaded into the Frothly environment?
Since I am looking for download I will use index="botsv2" sourcetype="stream:ftp"
To narrow the search down I need to find the method .


![image](https://github.com/Rory33160/Splunk-2-Part-of-the-Blue-Primer-series/assets/47018034/b1963c73-4a49-4359-984c-21f8eb7feb98)


According ChatGPT  RETR is the most likely method when the sourcetype is FTP. We used this method to narrow the search

![image](https://github.com/Rory33160/Splunk-2-Part-of-the-Blue-Primer-series/assets/47018034/f4325c1c-227c-40e6-8b7b-64c64e4e3b64)

What is the first and last name of the poor innocent sap who was implicated in the metadata of the file that executed PowerShell Empire on the first victim's workstation? Answer example: John Smith
The metadata from Virus Total

![image](https://github.com/Rory33160/Splunk-2-Part-of-the-Blue-Primer-series/assets/47018034/d7b8d046-17a1-4748-af20-eb32a7f57e1a)

Within the document, what kind of points is mentioned if you found the text?

This is given as a link in the question, https://app.any.run/

![image](https://github.com/Rory33160/Splunk-2-Part-of-the-Blue-Primer-series/assets/47018034/440ff835-9ae1-4f98-aecf-363f32875da8)

To maintain persistence in the Frothly network, Taedonggang APT configured several Scheduled Tasks to beacon back to their C2 server. What single webpage is most contacted by these Scheduled Tasks? Answer example: index.php or images.html

The given search index="botsv2" schtasks.exe returned 103 results.
To narrow the results down we will go to all fields and see if there is one related to commands.
 
These are the suspicious commands under command line.
Commands 6 to 8 that there is a daily command through Powershell

![image](https://github.com/Rory33160/Splunk-2-Part-of-the-Blue-Primer-series/assets/47018034/74f116ce-e802-485b-b6f2-63cd66e55be2)


To narrow down our search we’ll use 

index="botsv2" \\Software\\Microsoft\\Network because this where the command is running.
index="botsv2" \\Software\\Microsoft\\Network sourcetype=WinRegistry or 
index="botsv2" schtasks.exe powershell
There are 6 results and the three of interest has the base64 that we can convert on Cyberchef to get the answer.
Process.php

![image](https://github.com/Rory33160/Splunk-2-Part-of-the-Blue-Primer-series/assets/47018034/bb3652ed-202f-4d24-b7e4-aa4fd75c8406)








