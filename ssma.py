#!/usr/bin/env python3

import argparse
import os
from magic import Magic
from src import colors
from src.check import is_malware, is_file_packed, check_crypto, is_antidb_antivm, is_malicious_document
from src.check_file import PEScanner, file_info
from src.check_updates import check_internet_connection, download_yara_rules_git, update_me
from src.check_virustotal import virustotal
from src.file_strings import get_strings

print(colors.CYAN + """
███████╗███████╗███╗   ███╗ █████╗
██╔════╝██╔════╝████╗ ████║██╔══██╗ Simple
███████╗███████╗██╔████╔██║███████║ Static
╚════██║╚════██║██║╚██╔╝██║██╔══██║ Malware
███████║███████║██║ ╚═╝ ██║██║  ██║ Analyzer
╚══════╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝ v0.1
""" + colors.RESET)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Simple Static Malware Analyzer")
    parser.add_argument("filename", help="/path/to/file")
    parser.add_argument("-k", "--api-key", help="Virustotal API key")
    parser.add_argument("-d", "--document", help="check document/MS Office file", action="store_true")
    parser.add_argument("-u", "--update", help="Update SSMA", action="store_true")
    args = parser.parse_args()
    internet_connection = check_internet_connection()
    if args.update and internet_connection:
        try:
            update_me()
        except Exception as e:
            print(e, '\n')
    filetype = Magic(mime=True).from_file(args.filename)
    if filetype == 'application/x-dosexec':
        pe = PEScanner(filename=args.filename)
        print(colors.BOLD + colors.YELLOW + "File Details: " + colors.RESET)
        for n in pe.file_info():
            print('\t', n)
        print()
        print("================================================================================")
        if input("Continue? [Y/n] ") is 'n':
            exit()
        print()
        check_date_result = pe.check_date()
        if check_date_result:
            print(check_date_result)
            print()
            print("================================================================================")
            if input("Continue? [Y/n] ") is 'n':
                exit()
            print()
        check_imports_result = pe.check_imports()
        if check_imports_result:
            print(
                colors.BOLD + colors.YELLOW + "This file contains a list of Windows functions commonly used by malware.\nFor more information use the Microsoft documentation.\n" + colors.RESET)

            for n in check_imports_result:
                n = n.split(":")
                print('\t' + colors.LIGHT_RED + n[0] + colors.RESET + " - " + n[1])
            print()
            print("================================================================================")
            if input("Continue? [Y/n] ") is 'n':
                exit()
            print()
    else:
        print(colors.BOLD + colors.YELLOW + "File Details: " + colors.RESET)
        for n in file_info(args.filename):
            print('\t', n)
        print()
        print("================================================================================")
        if input("Continue? [Y/n] ") is 'n':
            exit()
        print()
    if args.api_key and internet_connection:
        virus_check = virustotal(args.filename, args.api_key)
        if virus_check[0] == "scan_result":
            print(colors.BOLD + colors.YELLOW + "Virustotal:" + colors.RESET)
            for n in virus_check[1]:
                n = n.split("-")
                print('\t' + colors.CYAN + n[0] + colors.RESET + "-" + colors.LIGHT_RED + n[1] + colors.RESET)
            print()
            print("================================================================================")
            if input("Continue? [Y/n] ") is 'n':
                exit()
            print()
        elif virus_check[0] == "permalink":
            if virus_check[1]:
                print(colors.LIGHT_BLUE + "Your file is being analysed." + colors.RESET)
                print(colors.BOLD + "VirusTotal link: " + colors.RESET, virus_check[1][0])
                print()
                print("================================================================================")
                if input("Continue? [Y/n] ") is 'n':
                    exit()
                print()
        elif not internet_connection:
            print(colors.RED + "No internet connection" + colors.RESET)
            print("================================================================================")
            if input("Continue? [Y/n] ") is 'n':
                exit()
            print()
        else:
            pass

    strings = get_strings(filename=args.filename).get_result()
    if strings[0]:
        print(colors.BOLD + colors.YELLOW + "Website links in stings of file: " + colors.RESET)
        for n in strings[0]:
            print('\t', n)
        print()
        print("================================================================================")
        if input("Continue? [Y/n] ") is 'n':
            exit()
        print()
    if strings[1]:
        print(colors.BOLD + colors.YELLOW + "IP addresses in strings of file: " + colors.RESET)
        for n in strings[1]:
            print('\t', n)
        print()
        print("================================================================================")
        if input("Continue? [Y/n] ") is 'n':
            exit()
        print()
    if strings[2]:
        print(colors.BOLD + colors.YELLOW + "E-Mail addresses in strings of file:" + colors.RESET)
        for n in strings[2]:
            print('\t', n)
        print()
        print("================================================================================")
        if input("Continue? [Y/n] ") is 'n':
            exit()
        print()
    if filetype == 'application/x-dosexec' or args.document:
        print(
            colors.BOLD + colors.YELLOW + "Scan file using Yara-rules.\nWith Yara rules you can create a \"description\" of malware families to detect new samples.\n" + colors.BOLD + colors.CYAN + "\tFor more information: https://virustotal.github.io/yara/\n" + colors.RESET)
        if not os.path.exists("rules"):
            os.mkdir("rules")
        if not os.path.exists("rules_compiled"):
            os.mkdir("rules_compiled")
        if not os.listdir("rules"):
            print(colors.BOLD + colors.CYAN + "Downloading Yara-rules... \n" + colors.RESET)
            download_yara_rules_git()
            print()
        else:
            if input(
                                            colors.BOLD + colors.GREEN + "Would you like to update Yara-Rules? [Y/n] " + colors.RESET) is not 'n':
                download_yara_rules_git()
                print()
        if filetype == 'application/x-dosexec':
            malicious_software = is_malware(filename=args.filename)
            if malicious_software:
                print(
                    colors.BOLD + colors.YELLOW + "These Yara rules specialised on the identification of well-known malware.\nResult: " + colors.RESET)
                for n in malicious_software:
                    print('\t', n)
                print()
                print("================================================================================")
                if input("Continue? [Y/n] ") is 'n':
                    exit()
                print()
            packed = is_file_packed(filename=args.filename)
            if packed:
                print(
                    colors.BOLD + colors.YELLOW + "These Yara Rules aimed to detect well-known sofware packers, that can be used by malware to hide itself.\nResult: " + colors.RESET)
                for n in packed:
                    print('\t', n)
                print()
                print("================================================================================")
                if input("Continue? [Y/n] ") is 'n':
                    exit()
                print()
            crypto = check_crypto(filename=args.filename)
            if crypto:
                print(
                    colors.BOLD + colors.YELLOW + "These Yara rules aimed to detect the existence of cryptographic algoritms." + colors.RESET)
                print(colors.YELLOW + "Detected cryptographic algorithms: " + colors.RESET)
                for n in crypto:
                    print('\t', n)
                print()
                print("================================================================================")
                if input("Continue? [Y/n] ") is 'n':
                    exit()
                print()
            anti_vm = is_antidb_antivm(filename=args.filename)
            if anti_vm:
                print(
                    colors.BOLD + colors.YELLOW + "These Yara Rules aimed to detect anti-debug and anti-virtualization techniques used by malware to evade automated analysis.\nResult: " + colors.RESET)
                for n in anti_vm:
                    print('\t', n)
                print()
                print("================================================================================")
                if input("Continue? [Y/n] ") is 'n':
                    exit()
                print()

        if args.document:
            document_result = is_malicious_document(filename=args.filename)
            print(
                colors.BOLD + colors.YELLOW + "These Yara Rules to be used with documents to find if they have been crafted to leverage malicious code.\nResult: " + colors.RESET)
            if document_result:
                for n in document_result:
                    print('\t', n)
                print("================================================================================")
                if input("Continue? [Y/n] ") is 'n':
                    exit()
                print()
            else:
                print(colors.BOLD + "\tNothing found" + colors.RESET)
                print("================================================================================")
                exit()
