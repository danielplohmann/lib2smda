import os
import re
import sys
import json
import hashlib

from tqdm import tqdm
from smda.common.SmdaReport import SmdaReport

import config
from lib2smda.Lib2SmdaConfig import Lib2SmdaConfig
from lib2smda.Lib2SmdaConverter import Lib2SmdaConverter


def libfile2smda(converter, input_filepath, output_folder):
    file_sha256 = ""
    with open(input_filepath, "rb") as fin:
        file_sha256 = hashlib.sha256(fin.read()).hexdigest()
    if input_filepath.endswith(".a") or input_filepath.endswith(".lib"):
        converter.ensureEmptyTmpDir(lib2smda_config.lib2smda_tmp_root)
        # unpack lib file into obj
        print(f"unpacking library file: {input_filepath}")
        extracted_obj_files = converter.extractObjectFiles(input_filepath, extension=".obj")
    elif input_filepath.endswith(".o") or input_filepath.endswith(".obj"):
        extracted_obj_files = {input_filepath: input_filepath}
    print(f"found {len(extracted_obj_files)} *.obj files.")
    # disassemble obj, dll, exe
    print("disassembling...")
    num_functions = 0
    smda_reports = []
    for obj_name, obj_filepath in sorted(extracted_obj_files.items()):
        print(obj_filepath)
        smda_report = converter.getSmdaReportFromIda(obj_filepath)
        smda_reports.append(smda_report)
        if smda_report:
            num_functions += smda_report.num_functions
    print(f"Total functions: {num_functions}")
    merged_report = converter.mergeSmdaReports(smda_reports)
    if merged_report:
        merged_report.sha256 = file_sha256
        merged_report.filename = os.path.basename(input_filepath)
    if merged_report and num_functions:
        with open(output_folder + os.sep + os.path.basename(input_filepath) + ".smda", "w") as fout:
            json.dump(merged_report.toDict(), fout, indent=1, sort_keys=True)


if __name__ == "__main__":
    this_path = str(os.path.abspath(os.sep.join([str(os.path.abspath(__file__)), ".."])))
    ida_interact = os.sep.join([this_path, "ida_interact.py"])
    lib2smda_config = Lib2SmdaConfig(this_path, config.LIB2SMDA_TMP_ROOT, ida_interact, config.IDA_ROOT)
    # initialize converter
    converter = Lib2SmdaConverter(lib2smda_config)
    output_path = os.sep.join([this_path, "output"])
    converter.ensureDirExists(output_path)
    sha256_by_libfile = {}
    smda_files_by_dirname = {}
    for root, dirs, files in sorted(os.walk(sys.argv[1], topdown=False)):
        for filename in sorted(files):
            filepath = os.path.abspath(root + os.sep + filename)
            lib_dirname = os.path.dirname(filepath)
            if (filepath.endswith(".obj") or filepath.endswith(".lib"))  and "/lib/" in filepath:
                file_sha256 = ""
                with open(filepath, "rb") as fin:
                    sha256_by_libfile[filepath] = hashlib.sha256(fin.read()).hexdigest()
    print(f"Files found: {len(sha256_by_libfile)}")
    for libfile, sha256 in sha256_by_libfile.items():
        libfile2smda(converter, libfile, output_path)
    input_foldername = sys.argv[1]
    if input_foldername.endswith(os.sep):
        input_foldername = input_foldername[:-1]
    input_foldername = input_foldername.split(os.sep)[-1]
    input_foldername = input_foldername.replace(" ", "_")
    with open(input_foldername + ".json", "w") as fout:
        json.dump(sha256_by_libfile, fout, indent=1, sort_keys=True)
