import os
import re
import sys
import time
import json
import shutil
import zipfile
import subprocess
from collections import Counter
from copy import deepcopy
import hashlib

import config
from lib2smda.Lib2SmdaConfig import Lib2SmdaConfig
from lib2smda.Lib2SmdaConverter import Lib2SmdaConverter


if __name__ == "__main__":
    this_path = str(os.path.abspath(os.sep.join([str(os.path.abspath(__file__)), ".."])))
    ida_interact = os.sep.join([this_path, "ida_interact.py"])
    lib2smda_config = Lib2SmdaConfig(this_path, config.LIB2SMDA_TMP_ROOT, ida_interact, config.IDA_ROOT)
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <path_to_exe_file>")
        sys.exit(1)
    if not os.path.isfile(sys.argv[1]):
        print(f"path {sys.argv[1]} is not a file")
        sys.exit(2)
    input_filepath = os.path.abspath(sys.argv[1])
    if not input_filepath.endswith(".exe"):
        print(f"path {sys.argv[1]} is not an *.exe")
        sys.exit(3)
    file_sha256 = ""
    with open(input_filepath, "rb") as fin:
        file_sha256 = hashlib.sha256(fin.read()).hexdigest()
    # initialize converter
    converter = Lib2SmdaConverter(lib2smda_config)
    smda_report = converter.getSmdaReportFromIda(input_filepath)
    print(f"Total functions: {smda_report.statistics.num_functions}")
    smda_report.sha256 = file_sha256
    smda_report.filename = os.path.basename(input_filepath)
    with open(input_filepath + ".smda", "w") as fout:
        json.dump(smda_report.toDict(), fout, indent=1, sort_keys=True)
