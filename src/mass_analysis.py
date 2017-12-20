"""
Mass analysis from a directory
Added by Yang
"""

import os


def start_scan(args):
    target_dir = os.path.abspath(args.directory)
    for root, _, filenames in os.walk(target_dir):
        for file in filenames:
            os.makedirs("analysis_report", exist_ok=True)
            filename = os.path.join(root, file)
            os.system("python3 ssma.py %s -r yes" % filename)
