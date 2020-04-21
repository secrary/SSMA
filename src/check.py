import os
import yara


def is_file_packed(filename):
    if not os.path.exists("rules_compiled/packers"):
        os.mkdir("rules_compiled/packers")
    for n in os.listdir("rules/packers"):
        rule = yara.compile("rules/packers/" + n)
        rule.save("rules_compiled/packers/" + n)
        rule = yara.load("rules_compiled/packers/" + n)
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
    if not os.path.exists("rules_compiled/antidebug_antivm"):
        os.mkdir("rules_compiled/antidebug_antivm")
    for n in os.listdir("rules/antidebug_antivm"):
        rule = yara.compile("rules/antidebug_antivm/" + n)
        rule.save("rules_compiled/antidebug_antivm/" + n)
        rule = yara.load("rules_compiled/antidebug_antivm/" + n)
        m = rule.match(filename)
        if m:
            return m


def check_crypto(filename):
    if not os.path.exists("rules_compiled/crypto"):
        os.mkdir("rules_compiled/crypto")
    for n in os.listdir("rules/crypto"):
        rule = yara.compile("rules/crypto/" + n)
        rule.save("rules_compiled/crypto/" + n)
        rule = yara.load("rules_compiled/crypto/" + n)
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
    if os.path.isdir(yara_file):
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
    elif os.path.isfile(yara_file):
        try:
            rule = yara.compile(yara_file)
            rule.save("rules_compiled/your_target/" + yara_file)
            rule = yara.load("rules_compiled/malware/" + yara_file)
            m = rule.match(filename)
            if m:
                return m
        except:
            pass
    else:
        return "[x] Wrong type of input!"
