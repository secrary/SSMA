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
from src.report import report


def start_scan(args):
    list = os.listdir(args.directory)
    if list:
        try:
            for l in list:
                filename = os.path.realpath(l)
                filetype = magic.from_file(args.filename, mime=True)
                if filetype == 'application/x-dosexec':
                    pe = PEScanner(filename=filename)
                elif filetype == 'application/x-executable':
                    elf = ELFScanner(filename=filename)
                else:
                    file = file_info(filename)

                file_report = report(filename)
                if not os.path.exists("analysis_report"):
                    os.mkdir("analysis_report")
                report.write(file_report)

        except:
            pass
