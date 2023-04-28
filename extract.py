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

from smda.common.SmdaReport import SmdaReport

import config
from utilities import ensure_dir, ensure_empty_tmp_dir


def merge_reports(smda_reports):
    merged_report = None
    if smda_reports:
        merged_report = deepcopy(smda_reports[0])
        linearized_functions = {}
        for smda_function in merged_report.getFunctions():
            linearized_functions[len(linearized_functions)] = smda_function
        merged_report.xcfg = linearized_functions
    if len(smda_reports) > 1:
        print(f"merging {len(smda_reports)} reports...")
        for smda_report in smda_reports[1:]:
            # add statistics
            merged_report.execution_time += smda_report.execution_time
            merged_report.statistics += smda_report.statistics
            merged_report.binary_size += smda_report.binary_size
            merged_report.binweight += smda_report.binweight
            for smda_function in smda_report.getFunctions():
                merged_report.xcfg[len(merged_report.xcfg)] = smda_function
    return merged_report


def produce_smda_report_from_ida(filepath):
    # paths
    obj_dirname = os.path.dirname(filepath)
    lib_filename = obj_dirname.split(os.sep)[-1]
    obj_filename = os.path.basename(filepath)[:-4]
    output_basedir = config.LIB2SMDA_TMP_ROOT + os.sep + "smda" + os.sep + lib_filename
    output_filepath = output_basedir + os.sep + obj_filename + ".smda"
    ensure_dir(output_basedir)
    ################
    if not os.path.exists(output_filepath):
        print("  converting IDA to SMDA: ", filepath)
        smda_output_dir = config.LIB2SMDA_TMP_ROOT + os.sep + "smda_tmp"
        ida_smda_path = smda_output_dir + os.sep + "ida_output_converted.json"
        ensure_dir(smda_output_dir)
        ida_interact_path = config.PROJECT_ROOT + os.sep + "ida_interact.py"
        # execution
        bitness = 64 if "_x64_" in filepath else 32
        bitness = 64
        ida_path = config.IDA_64_PATH if bitness == 64 else config.IDA_32_PATH
        command = [ida_path, "-c", "-A", "-S" + ida_interact_path, filepath]
        output = str(subprocess.check_output(command))
        smda_report = SmdaReport.fromFile(ida_smda_path)
        # kill potentially old file
        try:
            os.remove(ida_smda_path)
        except:
            pass
        # keep the groundtruth clean
        try:
            extension = ".i64" if bitness == 64 else ".idb"
            os.remove(filepath + extension)
        except:
            pass
        time.sleep(0.2)
        smda_report.is_library = True
        smda_report.filename = os.path.basename(filepath)
        with open(output_filepath, "w") as fout:
            json.dump(smda_report.toDict(), fout, indent=1, sort_keys=True)
    else:
        smda_report = SmdaReport.fromFile(output_filepath)
    return smda_report


def extract_obj_files(filepath):
    extracted_obj_files = {}
    # paths
    lib_filename = os.path.basename(filepath).rsplit(".", 1)[0]
    output_basedir = config.LIB2SMDA_TMP_ROOT + os.sep + lib_filename
    if os.path.exists(output_basedir):
        print("lib basedir already exists, skipping...")
        return {}
    tmp_filepath = ensure_empty_tmp_dir()
    # execute like: 7z e libzlib.lib -o/tmp/ar_output
    console_output = subprocess.Popen(["7z", "e", filepath, "-y", "-o%s" % tmp_filepath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out_stdio, out_stderr = console_output.communicate()
    time.sleep(0.2)
    has_obj_files = False
    for filename in sorted(os.listdir(tmp_filepath)):
        if "\\" in filename and filename.endswith(".obj"):
            if not has_obj_files:
                ensure_dir(output_basedir)
                has_obj_files = True
            component = lib_filename + "_" + filename.split("\\")[-1]
            extracted_obj_filepath = output_basedir + os.sep + lib_filename + "_" + filename.split("\\")[-1]
            shutil.move(tmp_filepath + os.sep + filename, extracted_obj_filepath)
            extracted_obj_files[component] = extracted_obj_filepath
            time.sleep(0.5)
        else:
            pass
            # print(f"Skipping Non-Windows filename for OBJ file: {filename}")
    if has_obj_files and os.path.exists(tmp_filepath + os.sep + "1.txt"):
        shutil.move(tmp_filepath + os.sep + "1.txt", output_basedir + os.sep + lib_filename + "_metadata.txt")
        time.sleep(0.2)
    return extracted_obj_files


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <path_to_lib_file> <opt:family> <opt:version>")
        sys.exit(1)
    if not os.path.isfile(sys.argv[1]):
        print(f"path {sys.argv[1]} is not a file")
        sys.exit(2)
    input_filepath = os.path.abspath(sys.argv[1])
    if not (input_filepath.endswith(".lib") or input_filepath.endswith(".a")):
        print(f"path {sys.argv[1]} is not a *.lib or *.a file")
        sys.exit(3)
    file_sha256 = ""
    with open(input_filepath, "rb") as fin:
        file_sha256 = hashlib.sha256(fin.read()).hexdigest()
    function_counts = Counter()
    # unpack lib file into obj
    print("unpacking library file...")
    extracted_obj_files = extract_obj_files(input_filepath)
    print(f"found {len(extracted_obj_files)} *.obj files.")
    # disassemble obj, dll, exe
    print("disassembling...")
    num_functions = 0
    smda_reports = []
    for obj_name, obj_filepath in sorted(extracted_obj_files.items()):
        print(obj_filepath)
        smda_report = produce_smda_report_from_ida(obj_filepath)
        smda_reports.append(smda_report)
        num_functions += smda_report.num_functions
    print(f"Total functions: {num_functions}")
    merged_report = merge_reports(smda_reports)
    if merged_report:
        merged_report.sha256 = file_sha256
        merged_report.filename = os.path.basename(input_filepath)
    with open(input_filepath + ".smda", "w") as fout:
        json.dump(merged_report.toDict(), fout, indent=1, sort_keys=True)
