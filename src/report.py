"""
Generate a malware analysis report in json format.
Added by Yang
"""

import os
import json
from src.check_strings import ascii_strings, unicode_strings


class pe_report:
    def __init__(self, pe, report, strings):
        self.filename = pe.filename
        self.file_info = pe.file_info(report, True)
        self._tsl = pe.checkTSL()
        self.check_imports = pe.check_imports()
        self.check_date = pe.check_date(True)
        self.sections_analysis = pe.sections_analysis(report)
        self.check_file_header = pe.check_file_header(report)
        self.ascii_strings = ascii_strings(self.filename, strings)
        self.unicode_strings = unicode_strings(self.filename, strings)

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
            "malware_domains": self.domains,
            "ascii_strings": self.ascii_strings,
            "unicode_strings": self.unicode_strings
        }

        with open("analysis_report/" + os.path.basename(self.filename) + ".json", "w") as f:
            json.dump(obj, f, indent=4)

    def dump(self):
        obj = {
            "filename": os.path.basename(self.filename),
            "file_info": self.file_info,
            "TSL": self._tsl,
            "sections": self.sections_analysis,
            "file_header": self.check_file_header,
            "date": self.check_date,
            "imports": self.check_imports,
            "yara_results": self.yara,
            "malware_domains": self.domains,
            "ascii_strings": self.ascii_strings,
            "unicode_strings": self.unicode_strings
        }
        return json.dumps(obj, indent=4, sort_keys=False)

class elf_report:
    def __init__(self, elf, report):
        self.filename = elf.filename
        self.file_info = elf.file_info(report)
        self.checksec = elf.checksec()
        self.dependencies = elf.dependencies().read().decode('utf-8')
        self.elf_header = elf.elf_header().read().decode('utf-8')
        self.program_header = elf.program_header().read().decode('utf-8')
        self.section_header = elf.section_header().read().decode('utf-8')
        self.symbols = elf.symbols().read().decode('utf-8')
        self.ascii_strings = ascii_strings(self.filename)
        self.unicode_strings = unicode_strings(self.filename)

    def domains(self, domains):
        self.domains = domains

    def yara(self, yara):
        self.yara = yara

    def write(self):
        obj = {
            "filename": os.path.basename(self.filename),
            "file_info": self.file_info,
            "checksec": self.checksec,
            "dependencies": self.dependencies,
            "elf_header": self.elf_header,
            "program_header": self.program_header,
            "section_header": self.section_header,
            "symbols": self.symbols,
            "yara_results": self.yara,
            "malware_domains": self.domains,
            "ascii_strings": self.ascii_strings,
            "unicode_strings": self.unicode_strings
        }

        with open("analysis_report/" + os.path.basename(self.filename) + ".json", "w") as f:
            json.dump(obj, f, indent=4)

    def dump(self):
        obj = {
            "filename": os.path.basename(self.filename),
            "file_info": self.file_info,
            "checksec": self.checksec,
            "dependencies": self.dependencies,
            "elf_header": self.elf_header,
            "program_header": self.program_header,
            "section_header": self.section_header,
            "symbols": self.symbols,
            "yara_results": self.yara,
            "malware_domains": self.domains,
            "ascii_strings": self.ascii_strings,
            "unicode_strings": self.unicode_strings
        }

        return json.dumps(obj, indent=4, sort_keys=False)

class others_report:
    def __init__(self, other):
        self.filename = os.path.basename(other[0])
        self.file_info = other
        self.ascii_strings = ascii_strings(self.filename)
        self.unicode_strings = unicode_strings(self.filename)

    def domains(self, domains):
        self.domains = domains

    def yara(self, yara):
        self.yara = yara

    def write(self):
        obj = {
            "filename": self.filename,
            "file_info": self.file_info,
            "yara_results": self.yara,
            "malware_domains": self.domains,
            "ascii_strings": self.ascii_strings,
            "unicode_strings": self.unicode_strings
        }

        with open("analysis_report/" + os.path.basename(self.filename) + ".json", "w") as f:
            json.dump(obj, f, indent=4)

    def dump(self):
        obj = {
            "filename": self.filename,
            "file_info": self.file_info,
            "yara_results": self.yara,
            "malware_domains": self.domains,
            "ascii_strings": self.ascii_strings,
            "unicode_strings": self.unicode_strings
        }

        return json.dumps(obj, indent=4, sort_keys=False)
