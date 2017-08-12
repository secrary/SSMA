"""
MARKDOWN TEMPLATE
Added by Pielco11
"""

class MarkDown:
    def __init__(self, nSections, nFunctions):
        self.table  = "#### SSMA"+"\n"
        self.table += "| Sections      | Functions   |\n"
        self.table += "|:-------------:|:-----------:|\n"
        self.table += "| " + str(nSections) + " | " + str(nFunctions) + " |\n"

    def write(self):
        return self.table