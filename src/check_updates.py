import os
import socket
import git


def check_internet_connection():
    try:
        host = socket.gethostbyname("www.google.com")
        s = socket.create_connection((host, 80), 2)
        return True
    except:
        pass
    return False


def download_yara_rules_git():
    if not os.listdir("rules"):
        git.Git().clone("https://github.com/Yara-Rules/rules")
    else:
        g = git.cmd.Git("rules")
        g.pull()


def update_me():  # git pull
    g = git.cmd.Git(".")
    g.pull()

