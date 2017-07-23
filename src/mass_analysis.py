"""
Mass analysis from a directory
Added by Yang
"""

import os

def start_scan(args):
    dir = os.path.abspath(args.directory)
    list = os.listdir(dir)
    if list:
        for root, _, filenames in os.walk(dir):
            for file in filenames:
                filename = os.path.join(root, file)

                if not os.path.exists("analysis_report"):
                    os.mkdir("analysis_report")

                os.system("python3 ssma.py -f %s -r yes" % filename)
