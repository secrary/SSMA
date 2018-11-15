import re
from urllib.parse import urlparse
import subprocess

from ext.validate_email import validate_email


def is_ip(list_of_strings):
    ipv4_pattern = re.compile(
        r'((([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])[ (\[]?(\.|dot)[ )\]]?){3}([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5]))')

    f = filter(ipv4_pattern.match, list_of_strings)

    return list(f)


def is_website(list_of_strings):
    list_of_web_addresses = []

    for n in list_of_strings:
        try:
            netloc = urlparse(n.split()[0]).netloc
            if netloc and "." in netloc and not netloc.startswith(".") and not netloc.endswith("."):
                list_of_web_addresses.append(netloc)
        except:
            pass

    list_of_web_addresses = set(list_of_web_addresses)

    return list_of_web_addresses


def is_email(list_of_strings):
    email_pattern = re.compile(r'(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)')

    f = filter(email_pattern.match, list_of_strings)
    F = []
    for e in list(f):
        if validate_email(e):
            F.append(e)

    return F


def ascii_strings(filename, enable):
    if not enable:
        strings_list = ""
    else:
        output = subprocess.check_output(["strings", "-a", filename])
        strings_list = list(output.decode("utf-8").split('\n'))
    return strings_list


def unicode_strings(filename, enalble):
    if not enalble:
        strings_list = ""
    else:
        output = subprocess.check_output(["strings", "-a", "-el", filename])
        strings_list = list(output.decode("utf-8").split('\n'))
    return strings_list
