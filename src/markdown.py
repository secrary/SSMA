"""
MARKDOWN TEMPLATE
Added by Pielco11
"""

class MarkDown:
    def __init__(self, [Sections, Functions, Flags, Doms, IPs, Emails]):
        self.max        = self.findMax([Sections, Functions, Flags, Doms, IPs, Emails])
        self.nSections  = str(len(Sections))
        self.nFunctions = str(len(Functions))
        self.nFlags     = str(len(Flags))
        self.nDoms      = str(len(Doms.get("normal_domains") + Doms.get("malware_domains")))
        self.lDoms      = []
        self.nIPs       = str(len(IPs))
        self.nEmails    = str(len(Emails))
        self.table      = "#### SSMA"+"\n"
        self.table     += "| Sections          | Functions          | Flags          | Doms          | IPs          | Emails          |\n"
        self.table     += "|:-----------------:|:------------------:|:--------------:|:-------------:|:------------:|:---------------:|\n"
        self.table     += "| " + nSections + " | " + nFunctions + " | " + nFlags + " | " + nDoms + " | " + nIPs + " | " + nEmails + " |\n"
        self.getlDoms()

    def getlDoms(self, self.lDoms, [Sections, Functions, Flags, Doms, IPs, Emails]):
        for d in range(len(Doms.get("malware_domains"))):
            self.lDoms.append(Doms.get("malware_domains")[d])
        for d in range(len(Doms.get("normal_domains"))):
            self.lDoms.append(Doms.get("normal_domains")[d])

    def write(self):
        return self.table

    def findMax(self, [Sections, Functions, Flags, Doms, IPs, Emails]):
        max = []
        for arg in [Sections, Functions, Flags, Doms, IPs, Emails]:
            if len(arg) > len(max):
                max = arg
        return max

    def addRows(self, [Sections, Functions, Flags, Doms, IPs, Emails], self.max, self.table):
        for m in range(self.max):
            try:
                for s in enumerate(Sections):
                    if s[0] == m:
                        sec  = s[1][0]
                self.table += "| " sec + " | "
            except IndexError:
                self.table += "| | "
            try:
                self.table += Functions[m].split("^")[0][0:len(Functions[m].split("^")[0])-1] + " | "
            except IndexError:
                self.table += " | "
            try:
                self.table += Flags[m][0] + " | "
            except IndexError:
                self.table += " | "
            try:
                self.table += Doms[m] + " | "
            except IndexError:
                self.table += " | "
            try:
                self.table += IPs[m] + " | "
            except IndexError:
                self.table += " | "
            try:
                self.table += Emails[m] + " |"
            except IndexError:
                self.table += " |"
            self.table     += "\n"
