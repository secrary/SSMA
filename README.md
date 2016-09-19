# SSMA

[![Join the chat at https://gitter.im/simple_static_malware_analyzer/Lobby](https://badges.gitter.im/simple_static_malware_analyzer/Lobby.svg)](https://gitter.im/simple_static_malware_analyzer/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)   [![Build Status](https://travis-ci.org/secrary/SSMA.svg?branch=master)](https://travis-ci.org/secrary/SSMA)

SSMA is a simple malware analyzer written in Python 3. 
## Features:
* Analyze PE file's header and sections (number of sections, entropy of sections/PE file, suspicious section names, suspicious flags in the characteristics of the PE file and etc.)

* Searches for possible domains, e-mail addresses, IP addresses in the strings of the file.

* Checks if domains are blacklisted based on abuse.ch's Ransomware Domain Blocklist and malwaredomains.com's blocklist.

* Looks for Windows functions commonly used by malware.

* Get results from VirusTotal and/or upload files.

* Malware detection based on [Yara-rules](https://virustotal.github.io/yara/)

* Detect well-known software packers.

* Detect the existence of cryptographic algorithms.

* Detect anti-debug and anti-virtualization techniques used by malware to evade automated analysis.

* Find if documents have been crafted to leverage malicious code.


## Usage
```
git clone https://github.com/secrary/SSMA

cd SSMA

sudo pip3 install -r requirements.txt

python3 ssma.py -h
```
Additional:
  ssdeep - [Installation](https://python-ssdeep.readthedocs.io/en/latest/installation.html)

More: [Simple Static Malware Analyzer](https://secrary.com/SSMA)
