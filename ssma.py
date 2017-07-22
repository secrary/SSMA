#!/usr/bin/env python3

"""
@author:       Lasha Khasaia
@license:      GNU General Public License 3.0
@contact:      @_qaz_qaz
@Description:  SSMA - Simple Static Malware Analyzer
"""

import argparse
import os
import magic
import shutil
import elftools

from src import colors
from src.blacklisted_domain_ip import ransomware_and_malware_domain_check
from src.check import is_malware, is_file_packed, check_crypto, is_antidb_antivm, is_malicious_document, is_your_target
from src.check_file import PEScanner, ELFScanner, file_info
from src.check_updates import check_internet_connection, download_yara_rules_git
from src.check_virustotal import virustotal
from src.file_strings import get_strings
from src.mass_analysis import start_scan
from src.pe_report import pe_report, elf_report, others_report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Simple Static Malware Analyzer")
    parser.add_argument("-f", "--filename", help="/path/to/file")
    parser.add_argument("-k", "--api-key", help="Virustotal API key")
    parser.add_argument("-d", "--document", help="check document/MS Office file", action="store_true")
    parser.add_argument("-F", "--Flush", help="Flush output, no interrupt (on/off)")
    parser.add_argument("-u", "--update", help="Update Yara-Rules (yes/no)")
    parser.add_argument("-y", "--yara", help="Scan file with your Yara-Rule")
    parser.add_argument("-D", "--directory", help="Mass analysis from a dir (/path/)")
    parser.add_argument("-r", "--report", help="Generate json format report (yes/no/output)")

    args = parser.parse_args()
    if args.report == "output":
        pass
    else:
        print(colors.CYAN + """
███████╗███████╗███╗   ███╗ █████╗
██╔════╝██╔════╝████╗ ████║██╔══██╗ Simple
███████╗███████╗██╔████╔██║███████║ Static
╚════██║╚════██║██║╚██╔╝██║██╔══██║ Malware
███████║███████║██║ ╚═╝ ██║██║  ██║ Analyzer
╚══════╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝
""" + colors.RESET)
    if args.update == "yes":
        if os.path.exists("rules"):
            shutil.rmtree("rules")
        if os.path.exists("rules_compiled"):
            shutil.rmtree("rules_compiled")
            os.mkdir("rules_compiled")
        print(colors.BOLD + colors.CYAN + "[-] Updating Yara-Rules..." + colors.RESET)
        download_yara_rules_git()
        print(colors.BOLD + colors.GREEN + "[+] Updated for Yara-Rules!" + colors.RESET)
        print()
        if not args.filename:
            exit()
        else:
            pass
    else:
        pass
    try:
        os.path.realpath(args.filename)
    except:
        try:
            os.path.realpath(args.directory)
        except:
            print(colors.BOLD + colors.RED + "No option selected, run ssma.py -h")
            exit()

    internet_connection = check_internet_connection()

    # Added by Yang
    if args.directory and not args.filename:
        start_scan(args)
        exit()
    elif args.directory and args.filename:
        print(colors.BOLD + colors.RED + "option error, please select a file or directory, run ssma.py -h")
        exit()

    py_file_location = os.path.dirname(__file__)
    args.filename = os.path.realpath(args.filename)
    if py_file_location:
        os.chdir(py_file_location)
    filetype = magic.from_file(args.filename, mime=True)
    if filetype == 'application/x-dosexec':
        pe = PEScanner(filename=args.filename)
        if args.report == "output":
            print('{\"results\": {\n\t\"File Details\": {')
        else:
            print(colors.BOLD + colors.YELLOW + "File Details: " + colors.RESET)
        for n in pe.file_info(args.report):
            if args.report == "output":
                print('\t',n)
            else:
                print('\t',n)
        if args.report == "output":
            print("\t},")
        else:
            print()
            print("================================================================================")
            if args.Flush == "off":
                if input("Continue? [Y/n] ") is 'n':
                    exit()
            print()

        sections = pe.sections_analysis(args.report)
        if args.report == "output":
            pass
        else:
            print("================================================================================")
            if args.Flush == "off":
                if input("Continue? [Y/n] ") is 'n':
                    exit()
            print()

        _tls = pe.checkTSL()
        if _tls is not None:
            if args.report == "output":
                print("\t\t\".tls\": \"True\",\n\t},") # EDIT AFTER HANDLING SECTIONS
            else:
                print(colors.RED + "The executable contains a .tls section.\n" + colors.RESET + "A TLS callback can be used to execute code before the entry point \
                and therefore execute secretly in a debugger.")
                print("================================================================================")
                if args.Flush == "off":
                    if input("Continue? [Y/n] ") is 'n':
                        exit()
                print()

        check_file_header = pe.check_file_header(args.report)
        continue_message = False
        if check_file_header["debug"] == True:
            continue_message = True
            print( # MAYBE A DUPLICATE WITH "check_file.py" #323 ?
                colors.LIGHT_RED + "File contains some debug information, in majority of regular PE files, should not "
                                   "contain debug information" + colors.RESET + "\n")

        if any(tr[1] for tr in check_file_header["flags"]):
            continue_message = True
            if args.report == "output":
                found = 0
                for n in check_file_header["flags"]:
                    if n[1]:
                        found+=1
                        print("\t\"flags\": {\n\t\t\"flag\":"+' \"'+n[0]+'\",')
                print("\t\t\"found\": "+str(found)+"\n\t},")
            else:
                print(colors.LIGHT_RED + "Suspicious flags in the characteristics of the PE file: " + colors.RESET)
                for n in check_file_header["flags"]:
                    if n[1]:
                        print(colors.RED + n[0] + colors.RESET + " flag is set - {}".format(n[2]))
                print()
        if args.report == "output":
            pass
        else:
            if continue_message:
                print("================================================================================")
                if args.Flush == "off":
                    if input("Continue? [Y/n] ") is 'n':
                        exit()
            print()

        check_date_result = pe.check_date()
        if check_date_result:
            if args.report == "output":
                print("\t\"com-date\": {\n\t\t\"date\": "+str(check_date_result.split(" ")[len(check_date_result.split(" "))-1]))
                print("\t},")
            else:
                print(check_date_result)
                print()
                print("================================================================================")
                if args.Flush == "off":
                    if input("Continue? [Y/n] ") is 'n':
                        exit()
                print()

        check_imports_result = pe.check_imports()
        if args.report == "output":
            print("\t\"Windows-Functions\": {")
            if check_imports_result:
                i = 0
                for n in check_imports_result:
                    n = n.split("^")
                    print("\t\t\""+n[0]+"\": \"True\",")
                    i+=1
                print("\t\t\"Total\": "+str(i)+"\n\t},")
        else:
            if check_imports_result:
                print(
                    colors.BOLD + colors.YELLOW + "This file contains a list of Windows functions commonly used by malware.\nFor more information use the Microsoft documentation.\n" + colors.RESET)

                for n in check_imports_result:
                    n = n.split("^")
                    print('\t' + colors.LIGHT_RED + n[0] + colors.RESET + " - " + n[1])
                print()
                print("================================================================================")
                if args.Flush == "off":
                    if input("Continue? [Y/n] ") is 'n':
                        exit()
                print()

        if args.report:
            if not os.path.exists("analysis_report"):
                os.mkdir("analysis_report")
            file_report = pe_report(pe, args.report)

    # ELF file -> Linux malware
    # Added by Yang
    # TODO
    elif filetype == 'application/x-executable':
        elf = ELFScanner(filename=args.filename)
        print(colors.BOLD + colors.YELLOW + "File Details: " + colors.RESET)

        if args.report:
            if not os.path.exists("analysis_report"):
                os.mkdir("analysis_report")
            file_report = elf_report(elf)
        pass

    else:
        print(colors.BOLD + colors.YELLOW + "File Details: " + colors.RESET)
        for n in file_info(args.filename):
            print('\t', n)
        print()
        print("================================================================================")
        if args.Flush == "off":
            if input("Continue? [Y/n] ") is 'n':
                exit()
            print()

        if args.report:
            if not os.path.exists("analysis_report"):
                os.mkdir("analysis_report")
            file_report = others_report(file_info(args.filename))

    if args.api_key and internet_connection:
        virus_check = virustotal(args.filename, args.api_key)
        if virus_check[0] == "scan_result":
            print(colors.BOLD + colors.YELLOW + "Virustotal:" + colors.RESET)
            for n in virus_check[1]:
                n = n.split("^")
                print('\t' + colors.CYAN + n[0] + colors.RESET + "-" + colors.LIGHT_RED + n[1] + colors.RESET)
            print()
            print("================================================================================")
            if args.Flush == "off":
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
    elif args.api_key and not internet_connection:
        print(colors.RED + "No internet connection" + colors.RESET)
        print("================================================================================")
        if args.Flush == "off":
            if input("Continue? [Y/n] ") is 'n':
                exit()
        print()

    strings = get_strings(filename=args.filename).get_result()
    if strings[0]:
        if args.report == "output":
            print("\t\"Domains\": {")
            total = 0
            mal_domains = ransomware_and_malware_domain_check(list(strings[0]))
            for n in mal_domains[0]:
                print("\t\t\""+str(n)+"\": \"True\",")
                total+=1
            if mal_domains[1]:
                for n in mal_domains[1]:
                    print("\t\t\""+str(n)+"\": \"True\",")
                    total+=1
            if mal_domains[2]:
                for n in mal_domains[2]:
                    print("\t\t\""+str(n)+"\": \"True\",")
                    total+=1
            print("\t\t\"Total\": "+str(total))
        else:
            print(colors.BOLD + colors.YELLOW + "Possible domains in strings of the file: " + colors.RESET)
            mal_domains = ransomware_and_malware_domain_check(list(strings[0]))
            for n in mal_domains[0]:
                print('\t', n)
            print()
            if mal_domains[1]:
                print("\t" + colors.RED + "Abuse.ch's Ransomware Domain Blocklist: " + colors.RESET)
                for n in mal_domains[1]:
                    print('\t', n)
                print()
            if mal_domains[2]:
                print(
                    "\t" + colors.RED + "A list of domains that are known to be used to propagate malware by http://www.malwaredomains.com/" + colors.RESET)
                for n in mal_domains[2]:
                    print('\t', n)
                print()
            print()
            print("================================================================================")
            if args.Flush == "off":
                if input("Continue? [Y/n] ") is 'n':
                    exit()
            print()

    if strings[1]:
        if args.report == "output":
            print("\t\"IP-addresses\": {")
            total = 0
            for n in strings[1]:
                print("\t\t\""+str(n)+"\": \"True\",")
                total+=1
            print("\t\t\"Total\": "+str(total))
        else:
            print(colors.BOLD + colors.YELLOW + "Possible IP addresses in strings of the file: " + colors.RESET)
            for n in strings[1]:
                print('\t', n)
            print()
            print("================================================================================")
            if args.Flush == "off":
                if input("Continue? [Y/n] ") is 'n':
                    exit()
            print()

    if strings[2]:
        if args.report == "output":
            print("\t\"Email\": {")
            total = 0
            for n in strings[2]:
                print("\t\t\""+str(n)+"\": \"True\",")
                total+=1
            print("\t\t\"Total\": "+str(total))
            print("\t}")
        else:
            print(colors.BOLD + colors.YELLOW + "Possible E-Mail addresses in strings of the file:" + colors.RESET)
            for n in strings[2]:
                print('\t', n)
            print()
            print("================================================================================")
            if args.Flush == "off":
                if input("Continue? [Y/n] ") is 'n':
                    exit()
            print()

    if args.report:
        mal_domains = ransomware_and_malware_domain_check(list(strings[0]))
        domains = {
            "normal_domains": list(mal_domains[0]),
            "malware_domains": list(mal_domains[1]) + list(mal_domains[2])
        }
        strings_result = {
            "Domains": domains,
            "IP-addresses": strings[1],
            "Email": strings[2]
        }
        file_report.domains(strings_result)

    if filetype == 'application/x-dosexec' or filetype == 'application/x-executable' or args.document:
        if args.report == "output":
            pass
        else:
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
                pass
            if filetype == 'application/x-dosexec':
                malicious_software = is_malware(filename=args.filename)
                if malicious_software:
                    print(
                        colors.BOLD + colors.YELLOW + "These Yara rules specialised on the identification of well-known malware.\nResult: " + colors.RESET)
                    for n in malicious_software:
                        try:
                            print("\t {} - {}".format(n, n.meta['description']))
                        except:
                            print('\t', n)
                    print()
                    print("================================================================================")
                    if args.Flush == "off":
                        if input("Continue? [Y/n] ") is 'n':
                            exit()
                    print()

                packed = is_file_packed(filename=args.filename)
                if packed:
                    print(
                        colors.BOLD + colors.YELLOW + "These Yara Rules aimed to detect well-known sofware packers, that can be used by malware to hide itself.\nResult: " + colors.RESET)
                    for n in packed:
                        try:
                            print("\t {} - {}".format(n, n.meta['description']))
                        except:
                            print('\t', n)
                    print()
                    print("================================================================================")
                    if args.Flush == "off":
                        if input("Continue? [Y/n] ") is 'n':
                            exit()
                    print()

                crypto = check_crypto(filename=args.filename)
                if crypto:
                    print(
                        colors.BOLD + colors.YELLOW + "These Yara rules aimed to detect the existence of cryptographic algoritms." + colors.RESET)
                    print(colors.YELLOW + "Detected cryptographic algorithms: " + colors.RESET)
                    for n in crypto:
                        try:
                            print("\t {} - {}".format(n, n.meta['description']))
                        except:
                            print('\t', n)
                    print()
                    print("================================================================================")
                    if args.Flush == "off":
                        if input("Continue? [Y/n] ") is 'n':
                            exit()
                    print()

                anti_vm = is_antidb_antivm(filename=args.filename)
                if anti_vm:
                    print(
                        colors.BOLD + colors.YELLOW + "These Yara Rules aimed to detect anti-debug and anti-virtualization techniques used by malware to evade automated analysis.\nResult: " + colors.RESET)
                    for n in anti_vm:
                        try:
                            print("\t {} - {}".format(n, n.meta['description']))
                        except:
                            print('\t', n)
                    print()
                    print("================================================================================")
                    if args.Flush == "off":
                        if input("Continue? [Y/n] ") is 'n':
                            exit()
                    print()

                your_target = {}
                if args.yara:
                    yara = str(os.path.realpath(args.yara))
                    your_target = is_your_target(args.filename, yara)
                    if your_target:
                        print(
                            colors.BOLD + colors.YELLOW + "These Yara Rules are created by yourself and aimed to detecte something you need.\nResult: " + colors.RESET)
                        for n in your_target:
                            try:
                                print("\t {} - {}".format(n, n.meta['description']))
                            except:
                                print('\t', n)
                        print()
                        print("================================================================================")
                        if args.Flush == "off":
                            if input("Continue? [Y/n] ") is 'n':
                                exit()
                        print()

                if args.report:
                    malicious_software_result = {}
                    packed_result = {}
                    crypto_result = {}
                    anti_vm_result = {}
                    your_target_result = {}
                    if malicious_software:
                        for n in malicious_software:
                            try:
                                malicious_software_result[str(n)] = n.meta['description']
                            except:
                                malicious_software_result[str(n)] = None
                    if packed:
                        for n in packed:
                            try:
                                packed_result[str(n)] = n.meta['description']
                            except:
                                packed_result[str(n)] = None
                    if crypto:
                        for n in crypto:
                            try:
                                crypto_result[str(n)] = n.meta['description']
                            except:
                                crypto_result[str(n)] = None
                    if anti_vm:
                        for n in anti_vm:
                            try:
                                anti_vm_result[str(n)] = n.meta['description']
                            except:
                                anti_vm_result[str(n)] = None
                    if your_target:
                        for n in your_target:
                            try:
                                your_target_result[str(n)] = n.meta['description']
                            except:
                                your_target_result[str(n)] = None
                    yara_result = {
                        "malicious_software": malicious_software_result,
                        "packed": packed_result,
                        "crypto": crypto_result,
                        "anti_vm": anti_vm_result,
                        "your_target": your_target_result
                    }
                    file_report.yara(yara_result)
                    file_report.write()

            if filetype == 'application/x-executable':
                your_target = {}
                if args.yara:
                    yara = str(os.path.realpath(args.yara))
                    your_target = is_your_target(args.filename, yara)
                    if your_target:
                        print(
                            colors.BOLD + colors.YELLOW + "These Yara Rules are created by yourself and aimed to detecte something you need.\nResult: " + colors.RESET)
                        for n in your_target:
                            try:
                                print("\t {} - {}".format(n, n.meta['description']))
                            except:
                                print('\t', n)
                        print()
                        print("================================================================================")
                        if args.Flush == "off":
                            if input("Continue? [Y/n] ") is 'n':
                                exit()
                        print()

                if args.report:
                    your_target_result = {}
                    if your_target:
                        for n in your_target:
                            try:
                                your_target_result[str(n)] = n.meta['description']
                            except:
                                your_target_result[str(n)] = None
                    yara_result = {
                        "your_target": your_target_result
                    }
                    file_report.yara(yara_result)
                    file_report.write()

            if args.document:
                malicious_document = is_malicious_document(filename=args.filename)
                print(
                    colors.BOLD + colors.YELLOW + "These Yara Rules to be used with documents to find if they have been crafted to leverage malicious code.\nResult: " + colors.RESET)
                if malicious_document:
                    for n in malicious_document:
                        try:
                            print("\t {} - {}".format(n, n.meta['description']))
                        except:
                            print('\t', n)
                    print("================================================================================")
                    if args.Flush == "off":
                        if input("Continue? [Y/n] ") is 'n':
                            exit()
                    print()

                your_target = {}
                if args.yara:
                    yara = str(os.path.realpath(args.yara))
                    your_target = is_your_target(args.filename, yara)
                    if your_target:
                        print(
                            colors.BOLD + colors.YELLOW + "These Yara Rules are created by yourself and aimed to detecte something you need.\nResult: " + colors.RESET)
                        for n in your_target:
                            try:
                                print("\t {} - {}".format(n, n.meta['description']))
                            except:
                                print('\t', n)
                        print()
                        print("================================================================================")
                        if args.Flush == "off":
                            if input("Continue? [Y/n] ") is 'n':
                                exit()
                        print()

                if args.report:
                    your_target_result = {}
                    if your_target:
                        for n in your_target:
                            try:
                                your_target_result[str(n)] = n.meta['description']
                            except:
                                your_target_result[str(n)] = None

                    malicious_document_result = {}
                    if malicious_document:
                        for n in malicious_document:
                            try:
                                malicious_document_result[str(n)] = n['description']
                            except:
                                malicious_document_result[str(n)] = None
                    yara_result = {
                        "malicious_document": malicious_document_result,
                        "your_target": your_target_result
                    }
                    file_report.yara(yara_result)
                    file_report.write()

                else:
                    print(colors.BOLD + "\tNothing found" + colors.RESET)
                    print("================================================================================")
                    exit()
    if args.report == "output":
        print("}}")
    else:
        print(colors.YELLOW + "Ups... " + colors.CYAN + "That's all :)" + colors.RESET + "\n")
