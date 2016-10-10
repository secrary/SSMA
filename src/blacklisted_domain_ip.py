import os
import urllib.request
import zipfile
from io import BytesIO
from urllib.parse import urlparse


def ransomware_and_malware_domain_check(list_of_domains):
    list_of = urllib.request.urlopen(
        "https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt").read().decode(errors='ignore').strip().split("\n")
    list_of_mal_domains = []

    for n in list_of:
        if n and not n.startswith("#"):
            list_of_mal_domains.append(n.strip())

    list_of = urllib.request.urlopen(
        "https://ransomwaretracker.abuse.ch/downloads/RW_URLBL.txt").read().decode(errors='ignore').strip().split("\n")
    list_of_mal_urls = []

    for n in list_of:
        if n and not n.startswith("#"):
            n = urlparse(n).netloc
            if n.startswith("www."):
                n = ".".join(n.split(".")[1:])
            list_of_mal_urls.append(n)

    list_of = set(list_of_mal_domains + list_of_mal_urls)

    mal_in_my_domains = []
    for mal_dom in list_of:
        for i, my_dom in enumerate(list_of_domains):
            if mal_dom in my_dom:
                mal_in_my_domains.append(mal_dom)
                list_of_domains[i] = mal_dom

    urlfile = urllib.request.urlopen("http://www.malware-domains.com/files/justdomains.zip")
    with zipfile.ZipFile(BytesIO(urlfile.read())) as z:
        z.extract("justdomains")
    my_malware_domains = []
    with open("justdomains", 'r') as malware_domains:
        list_of_malware_domains = malware_domains.readlines()
        for mal_dom in list_of_malware_domains:
            mal_dom = mal_dom.strip()
            if mal_dom:
                if mal_dom.startswith("www."):
                    mal_dom = ".".join(mal_dom.split(".")[1:])
                for i, my_domain in enumerate(list_of_domains):
                    if mal_dom in my_domain:
                        my_malware_domains.append(mal_dom)
                        list_of_domains[i] = mal_dom
    os.remove("justdomains")
    mal_in_my_domains = set(mal_in_my_domains)
    my_malware_domains = set(my_malware_domains)
    normal_domains = set(list_of_domains) - mal_in_my_domains - my_malware_domains

    return normal_domains, mal_in_my_domains, my_malware_domains
