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



def libfile2smda(converter, input_filepath, output_folder, version, output_filename):
    release_hashes = get_release_hashes(input_filepath)
    extracted_obj_files = {}
    if input_filepath.lower().endswith(".a"):
        converter.ensureEmptyTmpDir(lib2smda_config.lib2smda_tmp_root)
        # unpack a file into o
        print(f"unpacking library file: {input_filepath}")
        extracted_obj_files = converter.extractObjectFiles(input_filepath, extension=".o")
    elif input_filepath.lower().endswith(".lib"):
        converter.ensureEmptyTmpDir(lib2smda_config.lib2smda_tmp_root)
        # unpack lib file into obj
        print(f"unpacking library file: {input_filepath}")
        extracted_obj_files = converter.extractObjectFiles(input_filepath, extension=".obj")
    elif input_filepath.lower().endswith(".o") or input_filepath.lower().endswith(".obj"):
        extracted_obj_files = {input_filepath: input_filepath}
    print(f"found {len(extracted_obj_files)} *.o files.")
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
        merged_report.sha256 = release_hashes["sha256"]
        merged_report.sha1 = release_hashes["sha1"]
        merged_report.md5 = release_hashes["md5"]
        merged_report.filename = os.path.basename(input_filepath)
        merged_report.family = "aPLib"
        merged_report.version = version
    if merged_report and num_functions:
        with open(output_folder + os.sep + output_filename, "w") as fout:
            json.dump(merged_report.toDict(), fout, indent=1, sort_keys=True)

def get_release_hashes(input_abspath):
    release_hashes = {
        "sha256": "",
        "sha1": "",
        "md5": ""
    }
    with open(input_abspath, "rb") as fin:
        file_content = fin.read()
        release_hashes["sha256"] = hashlib.sha256(file_content).hexdigest()
        release_hashes["sha1"] = hashlib.sha1(file_content).hexdigest()
        release_hashes["md5"] = hashlib.md5(file_content).hexdigest()
    return release_hashes


if __name__ == "__main__":
    this_path = str(os.path.abspath(os.sep.join([str(os.path.abspath(__file__)), ".."])))
    ida_interact = os.sep.join([this_path, "ida_interact.py"])
    lib2smda_config = Lib2SmdaConfig(this_path, config.LIB2SMDA_TMP_ROOT, ida_interact, config.IDA_ROOT)
    # initialize converter
    converter = Lib2SmdaConverter(lib2smda_config)
    # run twice, once for each bitness
    input_abspath = os.path.abspath(sys.argv[1])
    for release_dir in sorted(os.listdir(input_abspath)):
        version = release_dir[6:]
        for platform in sorted(os.listdir(input_abspath + os.sep + release_dir)):
            for filename in sorted(os.listdir(input_abspath + os.sep + release_dir + os.sep + platform)):
                filepath = input_abspath + os.sep + release_dir + os.sep + platform + os.sep + filename
                print(f"processing: ", filepath)
                release_hashes = get_release_hashes(filepath)
                output_path = this_path + os.sep + "output" + os.sep + release_dir + os.sep + platform
                converter.ensureDirExists(output_path)
                output_filename = f"{release_dir}_{platform}_{filename}.smda"
                libfile2smda(converter, filepath, output_path, version, output_filename)
