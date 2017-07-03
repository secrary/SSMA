import os
import yara


def is_file_packed(filename):
    if not os.path.exists("rules_compiled/Packers"):
        os.mkdir("rules_compiled/Packers")
    for n in os.listdir("rules/Packers"):
        rule = yara.compile("rules/Packers/" + n)
        rule.save("rules_compiled/Packers/" + n)
        rule = yara.load("rules_compiled/Packers/" + n)
        m = rule.match(filename)
        if m:
            return m


def is_malicious_document(filename):
    if not os.path.exists("rules_compiled/Malicious_Documents"):
        os.mkdir("rules_compiled/Malicious_Documents")
    for n in os.listdir("rules/Malicious_Documents"):
        rule = yara.compile("rules/Malicious_Documents/" + n)
        rule.save("rules_compiled/Malicious_Documents/" + n)
        rule = yara.load("rules_compiled/Malicious_Documents/" + n)
        m = rule.match(filename)
        if m:
            return m


def is_antidb_antivm(filename):
    if not os.path.exists("rules_compiled/Antidebug_AntiVM"):
        os.mkdir("rules_compiled/Antidebug_AntiVM")
    for n in os.listdir("rules/Antidebug_AntiVM"):
        rule = yara.compile("rules/Antidebug_AntiVM/" + n)
        rule.save("rules_compiled/Antidebug_AntiVM/" + n)
        rule = yara.load("rules_compiled/Antidebug_AntiVM/" + n)
        m = rule.match(filename)
        if m:
            return m


def check_crypto(filename):
    if not os.path.exists("rules_compiled/Crypto"):
        os.mkdir("rules_compiled/Crypto")
    for n in os.listdir("rules/Crypto"):
        rule = yara.compile("rules/Crypto/" + n)
        rule.save("rules_compiled/Crypto/" + n)
        rule = yara.load("rules_compiled/Crypto/" + n)
        m = rule.match(filename)
        if m:
            return m


def is_malware(filename):
    if not os.path.exists("rules_compiled/malware"):
        os.mkdir("rules_compiled/malware")
    for n in os.listdir("rules/malware/"):
        if not os.path.isdir("./" + n):
            try:
                rule = yara.compile("rules/malware/" + n)
                rule.save("rules_compiled/malware/" + n)
                rule = yara.load("rules_compiled/malware/" + n)
                m = rule.match(filename)
                if m:
                    return m
            except:
                pass  # internal fatal error or warning
        else:
            pass


# Added by Yang
def is_your_target(filename, yara_file):
    if not os.path.exists("rules_compiled/your_target"):
        os.mkdir("rules_compiled/your_target")
    for n in os.listdir(yara_file):
        if not os.path.isdir("./" + n):
            try:
                rule = yara.compile(yara_file + "/" + n)
                rule.save("rules_compiled/your_target/" + n)
                rule = yara.load("rules_compiled/malware/" + n)
                m = rule.match(filename)
                if m:
                    return m
            except:
                pass
        else:
            pass
