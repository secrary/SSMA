# SSMA

SSMA is a simple malware analyzer written in Python 3. 
## Features:
* Searches for websites, e-mail addresses, IP addresses in the strings of the file.

* Looks for Windows functions commonly used by malware.

* Get results from VirusTotal and/or upload files.

* Malware detection based on Yara-rules - https://virustotal.github.io/yara/

* Detect well-known software packers.

* Detect the existence of cryptographic algorithms.

* Detect anti-debug and anti-virtualization techniques used by malware to evade automated analysis.

* Find if documents have been crafted to leverage malicious code.


## Usage
```
git clone https://github.com/secrary/SSMA

cd SSMA

pip install -r requirements.txt

python3 ssma.py -h
```
Additional:
  ssdeep - [Installation](https://python-ssdeep.readthedocs.io/en/latest/installation.html)

More: [Simple Static Malware Analyzer](https://secrary.com/SSMA)
