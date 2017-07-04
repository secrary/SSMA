"""
Generate a malware analysis report in json format.
Added by Yang
"""

import os
import json

# TODO
class pe_report:
    def __init__(self, pe):
        self.filename = pe.filename
        self.file_info = pe.file_info()
        self._tsl = pe.checkTSL()
        self.check_imports = pe.check_imports()
        self.check_date = pe.check_date()
        # self.sections_analysis = pe.sections_analysis()
        self.check_file_header = pe.check_file_header()

    def write(self):
        obj = {
            "filename": os.path.basename(self.filename),
            "file_info": self.file_info,
            "TSL": self._tsl,
            # self.sections_analysis(),
            "file_header": self.check_file_header,
            "date": self.check_date,
            "imports": self.check_imports,
        }

        with open("analysis_report/" + os.path.basename(self.filename) + ".json", "w") as f:
            json.dump(obj, f, indent=4)

class elf_report:
    def __init__(self, elf):
        pass
    def write(self):
        pass

class others_report:
    def __init__(self, other):
        self.filename = os.path.basename(other[0])
        self.file_info = other

    def write(self):
        obj = {
            "filename": self.filename,
            "file_info": self.file_info
        }

        with open("analysis_report/" + self.filename + ".json", "w") as f:
            json.dump(obj, f, indent=4)
