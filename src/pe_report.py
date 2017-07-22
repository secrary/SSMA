"""
Generate a malware analysis report in json format.
Added by Yang
"""

import os
import json


class pe_report:
    def __init__(self, pe, report):
        self.filename = pe.filename
        self.file_info = pe.file_info(report)
        self._tsl = pe.checkTSL()
        self.check_imports = pe.check_imports()
        self.check_date = pe.check_date()
        self.sections_analysis = pe.sections_analysis(report)
        self.check_file_header = pe.check_file_header(report)

    def domains(self, domains):
        self.domains = domains

    def yara(self, yara):
        self.yara = yara

    def write(self):
        obj = {
            "filename": os.path.basename(self.filename),
            "file_info": self.file_info,
            "TSL": self._tsl,
            "sections": self.sections_analysis,
            "file_header": self.check_file_header,
            "date": self.check_date,
            "imports": self.check_imports,
            "yara_results": self.yara,
            "malware_domains": self.domains
        }

        with open("analysis_report/" + os.path.basename(self.filename) + ".json", "w") as f:
            json.dump(obj, f, indent=4)


class elf_report:
    def __init__(self, elf):
        self.filename = elf.filename

    def domains(self, domains):
        self.domains = domains

    def yara(self, yara):
        self.yara = yara

    def write(self):
        obj = {
            "yara_results": self.yara,
            "malware_domains": self.domains
        }

        with open("analysis_report/" + os.path.basename(self.filename) + ".json", "w") as f:
            json.dump(obj, f, indent=4)



class others_report:
    def __init__(self, other):
        self.filename = os.path.basename(other[0])
        self.file_info = other

    def domains(self, domains):
        self.domains = domains

    def yara(self, yara):
        self.yara = yara

    def write(self):
        obj = {
            "filename": self.filename,
            "file_info": self.file_info,
            "yara_results": self.yara,
            "malware_domains": self.domains
        }

        with open("analysis_report/" + os.path.basename(self.filename) + ".json", "w") as f:
            json.dump(obj, f, indent=4)
