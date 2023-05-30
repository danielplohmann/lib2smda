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
        print(f"usage: {sys.argv[0]} <path_to_lib_file>")
        sys.exit(1)
    if not os.path.isfile(sys.argv[1]):
        print(f"path {sys.argv[1]} is not a file")
        sys.exit(2)
    input_filepath = os.path.abspath(sys.argv[1])
    if not (input_filepath.endswith(".lib") or input_filepath.endswith(".a")):
        print(f"path {sys.argv[1]} is not a *.lib or *.a file")
        sys.exit(3)
    # initialize converter
    converter = Lib2SmdaConverter(lib2smda_config)
    converter.ensureEmptyTmpDir(lib2smda_config.lib2smda_tmp_root)
    file_sha256 = ""
    with open(input_filepath, "rb") as fin:
        file_sha256 = hashlib.sha256(fin.read()).hexdigest()
    function_counts = Counter()
    # unpack lib file into obj
    print("unpacking library file...")
    extracted_obj_files = converter.extractObjectFiles(input_filepath)
    print(f"found {len(extracted_obj_files)} *.obj files.")
    # disassemble obj, dll, exe
    print("disassembling...")
    num_functions = 0
    smda_reports = []
    for obj_name, obj_filepath in sorted(extracted_obj_files.items()):
        print(obj_filepath)
        smda_report = converter.getSmdaReportFromIda(obj_filepath)
        smda_reports.append(smda_report)
        num_functions += smda_report.num_functions
    print(f"Total functions: {num_functions}")
    merged_report = converter.mergeSmdaReports(smda_reports)
    if merged_report:
        merged_report.sha256 = file_sha256
        merged_report.filename = os.path.basename(input_filepath)
    with open(input_filepath + ".smda", "w") as fout:
        json.dump(merged_report.toDict(), fout, indent=1, sort_keys=True)
