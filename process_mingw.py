import os
import re
import sys
import json
import hashlib
from copy import deepcopy

from tqdm import tqdm
from smda.common.SmdaReport import SmdaReport

import config
from lib2smda.Lib2SmdaConfig import Lib2SmdaConfig
from lib2smda.Lib2SmdaConverter import Lib2SmdaConverter


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
            # we should deduplicate here if we have an identical PIC hash and function_name, which happens for a bunch of MinGW
            # TODO maybe make this an execution parameter
            unique_functions = set()
            for smda_function in smda_report.getFunctions():
                if not (smda_function.pic_hash, smda_function.function_name) in unique_functions:
                    merged_report.xcfg[len(merged_report.xcfg)] = smda_function
                    unique_functions.add((smda_function.pic_hash, smda_function.function_name))
    return merged_report


def libfile2smda(converter, input_filepath, output_folder):
    file_sha256 = ""
    with open(input_filepath, "rb") as fin:
        file_sha256 = hashlib.sha256(fin.read()).hexdigest()
    if input_filepath.endswith(".a") or input_filepath.endswith(".lib"):
        converter.ensureEmptyTmpDir(lib2smda_config.lib2smda_tmp_root)
        # unpack lib file into obj
        print(f"unpacking library file: {input_filepath}")
        extracted_obj_files = converter.extractObjectFiles(input_filepath, extension=".o")
    elif input_filepath.endswith(".o") or input_filepath.endswith(".obj"):
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
    # run twice, once for each bitness
    input_abspath = os.path.abspath(sys.argv[1])
    for release_dir in os.listdir(input_abspath):
        if os.path.isdir(input_abspath + os.sep + release_dir):
            release_hashes = {
                "sha256": "",
                "sha1": "",
                "md5": ""
            }
            with open(input_abspath + os.sep + release_dir + ".7z", "rb") as fin:
                file_content = fin.read()
                release_hashes["sha256"] = hashlib.sha256(file_content).hexdigest()
                release_hashes["sha1"] = hashlib.sha1(file_content).hexdigest()
                release_hashes["md5"] = hashlib.md5(file_content).hexdigest()
            bitness_paths = ["/lib/", "/lib32/"]
            for bitness_path in bitness_paths:
                output_path = this_path + os.sep + "output" + os.sep + release_dir + os.sep + ("x64" if bitness_path == "/lib/" else "x86")
                converter.ensureDirExists(output_path)
                sha256_by_libfile = {}
                smda_files_by_dirname = {}
                for root, dirs, files in sorted(os.walk(input_abspath + os.sep + release_dir, topdown=False)):
                    for filename in sorted(files):
                        filepath = os.path.abspath(root + os.sep + filename)
                        lib_dirname = os.path.dirname(filepath)
                        if (filepath.endswith(".o") or filepath.endswith(".a"))  and "x86_64" in filepath and bitness_path in filepath:
                            file_sha256 = ""
                            with open(filepath, "rb") as fin:
                                sha256_by_libfile[filepath] = hashlib.sha256(fin.read()).hexdigest()
                print(f"Processing {release_dir}, found {len(sha256_by_libfile)} library files.")
                # for libfile, sha256 in sha256_by_libfile.items():
                #     libfile2smda(converter, libfile, output_path)

                # merge everything into one
                print("merging SMDA reports...")
                smda_reports = []
                for filename in os.listdir(output_path):
                    smda_report = SmdaReport.fromFile(output_path + os.sep + filename)
                    print(smda_report)
                    smda_reports.append(smda_report)
                merged_report = merge_reports(smda_reports)
                if merged_report:
                    merged_report.filename = release_dir + ".7z"
                    merged_report.sha256 = release_hashes["sha256"]
                    merged_report.sha1 = release_hashes["sha1"]
                    merged_report.md5 = release_hashes["md5"]
                    merged_report.family = "MinGW"
                    merged_report.version = release_dir
                    merged_report.statistics.num_functions = merged_report.num_functions
                    merged_report.statistics.num_basic_blocks = merged_report.num_instructions
                    merged_report.statistics.num_instructions = merged_report.num_instructions
                    merged_report.statistics.num_recursive_functions = 0
                    merged_report.statistics.num_leaf_functions = 0
                    merged_report.statistics.num_api_calls = 0
                    merged_report.statistics.num_function_calls = 0
                    merged_report.statistics.num_failed_functions = 0
                    merged_report.statistics.num_failed_instructions = 0
                with open(this_path + os.sep + "output" + os.sep + release_dir + "_" + ("x64" if bitness_path == "/lib/" else "x86") + ".smda", "w") as fout:
                    json.dump(merged_report.toDict(), fout, indent=1, sort_keys=True)
