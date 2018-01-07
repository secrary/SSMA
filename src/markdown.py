"""
MARKDOWN TEMPLATE
Added by Pielco11
"""

class MarkDown:
    def __init__(self, args):
        [Sections, Functions, Flags, Doms, IPs, Emails] = args
        self.max        = self.findMax([Sections, Functions, Flags, Doms, IPs, Emails])
        self.nSections  = str(len(Sections))
        self.nFunctions = str(len(Functions))
        self.nFlags     = str(len(Flags))
        self.nDoms      = str(len(Doms.get("normal_domains") + Doms.get("malware_domains")))
        self.lDoms      = []
        self.nIPs       = str(len(IPs))
        self.nEmails    = str(len(Emails))
        self.table      = "#### SSMA"+"\n"
        self.table     += "| Sections               | Functions               | Flags               | Doms               | IPs               | Emails               |\n"
        self.table     += "|:----------------------:|:-----------------------:|:-------------------:|:------------------:|:-----------------:|:--------------------:|\n"
        self.table     += "| " + self.nSections + " | " + self.nFunctions + " | " + self.nFlags + " | " + self.nDoms + " | " + self.nIPs + " | " + self.nEmails + " |\n"
        self.getlDoms(self.lDoms, [Sections, Functions, Flags, Doms, IPs, Emails])
        self.addRows([Sections, Functions, Flags, Doms, IPs, Emails])

    def getlDoms(self, lDoms, args):
        [Sections, Functions, Flags, Doms, IPs, Emails] = args
        for d in range(len(Doms.get("malware_domains"))):
            self.lDoms.append(Doms.get("malware_domains")[d])
        for d in range(len(Doms.get("normal_domains"))):
            self.lDoms.append(Doms.get("normal_domains")[d])

    def write(self):
        return self.table

    def findMax(self, args):
        [Sections, Functions, Flags, Doms, IPs, Emails] = args
        max = 0
        for arg in [Sections, Functions, Flags, Doms, IPs, Emails]:
            if len(arg) > max:
                max = len(arg)
        return max

    def addRows(self, args):
        [Sections, Functions, Flags, Doms, IPs, Emails] = args
        for m in range(self.max):
            try:
                if m < len(Sections):
                    for s, v in enumerate(Sections):
                        if s == m:
                            self.table += "| " + v + " | "
                else:
                    self.table += "| | "
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
            except KeyError:
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
