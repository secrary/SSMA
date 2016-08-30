import hashlib
import virus_total_apis


def virustotal(filename, api_key):  # ("info", result[])
    key = api_key
    result = []

    vt = virus_total_apis.PublicApi(key)

    md5 = hashlib.md5(open(filename, 'rb').read()).hexdigest()
    response = vt.get_file_report(md5)

    if response["response_code"] == 204:
        pass

    response_code_ = response["results"]["response_code"]

    if response_code_ == 1:
        for n in response["results"]["scans"]:
            if response["results"]["scans"][n]["detected"]:
                result.append("{} - {}".format(n, response["results"]["scans"][n]["result"]))
    elif response_code_ == -2:
        pass
    else:
        if input("Would you like to upload file to VirusTotal? [Y/n] ") is not "n":
            response = vt.scan_file(filename)
            result.append(response["results"]["permalink"])
        else:
            print()
    return ("scan_result", result) if response_code_ is 1 else ("permalink", result)
