import hashlib
import os
import time
import magic
import pefile

ssdeep_r = True
try:
    import ssdeep
except:
    ssdeep_r = False
    pass

from src import colors


class PEScanner:
    def __init__(self, filename):
        self.filename = filename
        self.pe = pefile.PE(self.filename)

        self.alerts = {
            'OpenProcess': "Opens a handle to another process running on the system. This handle can be used to read and write to the other process memory or to inject code into the other process.",
            'VirtualAllocEx': "A memory-allocation routine that can allocate memory in a remote process. Malware sometimes uses VirtualAllocEx as part of process injection",
            'WriteProcessMemory': "Used to write data to a remote process. Malware uses WriteProcessMemory as part of process injection.",
            'CreateRemoteThread': "Used to start a thread in a remote process (one other than the calling process). Launchers and stealth malware use CreateRemoteThread to inject code into a different process.",
            'ReadProcessMemory': "Used to read the memory of a remote process.",
            'CreateProcess': "Creates and launches a new process. If malware creates a new process, you will need to analyze the new process as well.",
            'WinExec': "Used to execute another program. If malware creates a new process, you will need to analyze the new process as well.",
            'ShellExecute': "Used to execute another program. If malware creates a new process, you will need to analyze the new process as well.",
            'HttpSendRequest': "Suggest that the PE file uses HTTP",
            'InternetReadFile': "Reads data from a previously opened URL",
            'InternetConnect': "PE file uses to establish connection",
            'CreateService': "Creates a service that can be started at boot time. Malware uses CreateService for persistence, stealth, or to load kernel drivers.",
            'StartService': "Starting a service",
            'accept': "Used to listen for incoming connections. This function indicates that the program will listen for incoming connections on a socket.",
            'AdjustTokenPrivileges': "Used to enable or disable specific access privileges. Malware that performs process injection often calls this function to gain additional permissions.",
            'VirtualProtectEx': "Changes the protection on a region of memory. Malware may use this function to change a read-only section of memory to an executable.",
            'SetWindowsHookEx': "Sets a hook function to be called whenever a certain event is called. Commonly used with keyloggers and spyware, this function also provides an easy way to load a DLL into all GUI processes on the system. This function is sometimes added by the compiler.",
            'SfcTerminateWatcherThread': "Used to disable Windows file protection and modify files that otherwise would be protected. SfcFileException can also be used in this capacity.",
            'FtpPutFile': "A high-level function for uploading a file to a remote FTP server.",
            'EnumProcesses': "Used to enumerate through running processes on the system. Malware often enumerates through processes to find a process to inject into.",
            'connect': "Used to connect to a remote socket. Malware often uses low-level functionality to connect to a command-and-control server.",
            'GetAdaptersInfo': "Used to obtain information about the network adapters on the system. Backdoors sometimes call GetAdaptersInfo as part of a survey to gather information about infected machines. In some cases, it’s used to gather MAC addresses to check for VMware as part of anti-virtual machine techniques.",
            'GetAsyncKeyState': "Used to determine whether a particular key is being pressed. Malware sometimes uses this function to implement a keylogger.",
            'GetKeyState': "Used by keyloggers to obtain the status of a particular key on the keyboard.",
            'InternetOpen': "Initializes the high-level Internet access functions."}

    def get_ssdeep(self):
        try:
            return ssdeep.hash_from_file(self.filename)
        except:
            pass
        return ''

    def check_date(self):
        val = self.pe.FILE_HEADER.TimeDateStamp
        pe_year = int(time.ctime(val).split()[-1])
        this_year = int(time.gmtime(time.time())[0])
        if pe_year > this_year or pe_year < 2000:
            return colors.RED + " [SUSPICIOUS COMPILATION DATE] - {}".format(this_year) + colors.RESET

    def file_info(self):
        info = []
        with open(self.filename, 'rb') as f:
            file = f.read()
            info.append("File: {}".format(self.filename))
            info.append("Size: {} bytes".format(os.path.getsize(self.filename)))
            info.append("Type: {}".format(magic.from_file(self.filename, mime=True)))
            info.append("MD5: {}".format(hashlib.md5(file).hexdigest()))
            info.append("SHA1: {}".format(hashlib.sha1(file).hexdigest()))
            if ssdeep_r:
                info.append("ssdeep: {}".format(self.get_ssdeep()))
            info.append("Date: {}".format(time.ctime(self.pe.FILE_HEADER.TimeDateStamp)))
        return info

    def check_imports(self):
        ret = []
        ret2 = []
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return ret
        for lib in self.pe.DIRECTORY_ENTRY_IMPORT:
            for imp in lib.imports:
                ret.append(imp.name)
        for n in ret:
            n = str(n)[2:-1]
            if any(map(n.startswith, self.alerts.keys())):
                for a in self.alerts:
                    if n.startswith(a):
                        ret2.append("{}:{}".format(n, self.alerts.get(a)))

        return ret2


def file_info(filename):
    info = []
    with open(filename, 'rb') as f:
        file = f.read()
        info.append("File: {}".format(filename))
        info.append("Size: {} bytes".format(os.path.getsize(filename)))
        info.append("Type: {}".format(magic.from_file(filename, mime=True)))
        info.append("MD5: {}".format(hashlib.md5(file).hexdigest()))
        info.append("SHA1: {}".format(hashlib.sha1(file).hexdigest()))
        if ssdeep_r:
            info.append("ssdeep: {}".format(ssdeep.hash_from_file(filename)))
    return info
