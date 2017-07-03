"""
Mass analysis from a directory
Added by Yang
"""

import os
import shutil
import json
import magic
import pefile

from src import colors
from src.blacklisted_domain_ip import ransomware_and_malware_domain_check
from src.check import is_malware, is_file_packed, check_crypto, is_antidb_antivm, is_malicious_document, is_your_target
from src.check_file import PEScanner, ELFScanner, file_info
from src.check_updates import check_internet_connection, download_yara_rules_git
from src.check_virustotal import virustotal
from src.file_strings import get_strings
from src.pe_report import pe_report, elf_report, others_report


def start_scan(args):
    dir = os.path.abspath(args.directory)
    list = os.listdir(dir)
    if list:
        for root, _, filenames in os.walk(dir):
            for file in filenames:
                filename = os.path.join(root, file)
                filetype = magic.from_file(filename, mime=True)

                if not os.path.exists("analysis_report"):
                    os.mkdir("analysis_report")
                if filetype == 'application/x-dosexec':
                    pe = PEScanner(filename=filename)

                    file_report = pe_report(pe)
                    file_report.write()

                elif filetype == 'application/x-executable':
                    elf = ELFScanner(filename=filename)

                    file_report = elf_report(elf)
                    file_report.write()

                else:
                    file = file_info(filename)

                    file_report = others_report(file)
                    file_report.write()
