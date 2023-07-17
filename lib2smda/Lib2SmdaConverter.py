import os
import re
import time
import json
import shutil
import zipfile
import logging
import subprocess
from copy import deepcopy

from smda.common.SmdaReport import SmdaReport

from lib2smda.Lib2SmdaConfig import Lib2SmdaConfig


class Lib2SmdaConverter(object):

    def __init__(self, config: Lib2SmdaConfig) -> None:
        self.config = config
        print(f"Ensureing empty tmp root: {self.config.lib2smda_tmp_root}")
        self.ensureEmptyTmpDir(self.config.lib2smda_tmp_root)
    
    def extractObjectFiles(self, filepath, extension=".obj"):
        extracted_obj_files = {}
        # paths
        output_basedir = os.sep.join([self.config.lib2smda_tmp_root, "obj_files"])
        self.ensureDirExists(output_basedir)
        tmp_filepath = self.ensureEmptyTmpDir()
        # execute like: 7z e libzlib.lib -o/tmp/ar_output
        console_output = subprocess.Popen(["7z", "e", filepath, "-y", "-o%s" % tmp_filepath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out_stdio, out_stderr = console_output.communicate()
        time.sleep(0.05)
        has_obj_files = False
        for filename in sorted(os.listdir(tmp_filepath)):
            # TODO not sure if we need to check for the backslash? that's from shiftmedia and windows lib files 
            if "\\" in filename and filename.endswith(extension):
                component = filename.split("\\")[-1]
                extracted_obj_filepath = output_basedir + os.sep + filename.split("\\")[-1]
                shutil.move(tmp_filepath + os.sep + filename, extracted_obj_filepath)
                extracted_obj_files[component] = extracted_obj_filepath
                has_obj_files = True
                time.sleep(0.1)
            elif filename.endswith(extension):
                component = filename
                extracted_obj_filepath = output_basedir + os.sep + filename
                shutil.move(tmp_filepath + os.sep + filename, extracted_obj_filepath)
                extracted_obj_files[component] = extracted_obj_filepath
                has_obj_files = True
                time.sleep(0.1)
            else:
                pass
                # print(f"Skipping Non-Windows filename for OBJ file: {filename}")
        if has_obj_files and os.path.exists(tmp_filepath + os.sep + "1.txt"):
            shutil.move(tmp_filepath + os.sep + "1.txt", output_basedir + os.sep + "_metadata.txt")
            time.sleep(0.05)
        return extracted_obj_files
    
    def mergeSmdaReports(self, smda_reports):
        merged_report = None
        if smda_reports:
            merged_report = deepcopy(smda_reports[0])
            linearized_functions = {}
            for smda_function in merged_report.getFunctions():
                linearized_functions[len(linearized_functions)] = smda_function
            merged_report.xcfg = linearized_functions
        if len(smda_reports) > 1:
            logging.info(f"merging {len(smda_reports)} reports...")
            for smda_report in smda_reports[1:]:
                # add statistics
                merged_report.execution_time += smda_report.execution_time
                merged_report.statistics += smda_report.statistics
                merged_report.binary_size += smda_report.binary_size
                merged_report.binweight += smda_report.binweight
                for smda_function in smda_report.getFunctions():
                    merged_report.xcfg[len(merged_report.xcfg)] = smda_function
        return merged_report
    
    def getSmdaReportFromIda(self, filepath):
        # paths
        obj_dirname = os.path.dirname(filepath)
        lib_filename = obj_dirname.split(os.sep)[-1]
        obj_filename = os.path.basename(filepath)[:-4]
        output_basedir = os.sep.join([self.config.lib2smda_tmp_root, "smda_reports"])
        output_filepath = os.sep.join([output_basedir, obj_filename + ".smda"])
        self.ensureDirExists(output_basedir)
        ################
        if not os.path.exists(output_filepath):
            logging.info("  converting IDA to SMDA: ", filepath)
            smda_output_dir =  os.sep.join([self.config.lib2smda_tmp_root, "ida_output"])
            ida_smda_path = os.sep.join([smda_output_dir, "ida_output_converted.json"])
            self.ensureDirExists(smda_output_dir)
            # execution
            bitness = 64 if "_x64_" in filepath else 32
            bitness = 64
            ida_path = self.config.ida64_path if bitness == 64 else self.config.ida32_path
            command = [ida_path, "-c", "-A", "-S" + self.config.ida_interact_path, filepath]
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
            time.sleep(0.1)
            smda_report.is_library = True
            smda_report.filename = os.path.basename(filepath)
            with open(output_filepath, "w") as fout:
                json.dump(smda_report.toDict(), fout, indent=1, sort_keys=True)
        else:
            smda_report = SmdaReport.fromFile(output_filepath)
        return smda_report

    def extractLibFilesFromZip(self, filepath):
        """
        In case our libfiles are nested somehow in a zip file, we can also extract that one first
        this was originally used to process files taken from shiftmedia, possibly needs adaption 
        """
        regex_version = r"(?P<version>\d+\.\d+(\.\d+)*(\-\d+)?([a-z])?)"
        extracted_lib_files = []
        pack_basedir = os.path.dirname(filepath)[:-4]
        lib_basedir = pack_basedir + os.sep + "lib"
        self.ensureDirExists(lib_basedir)
        pieces = os.path.basename(filepath[:-4]).split("_")
        family = pieces[0]
        msvc = pieces[-1]
        version = ".".join(pieces[1:-1])
        regexed_version = re.search(regex_version, version).group("version")
        if not regexed_version:
            print(f"[!] could not extract version for {filepath}")
        with zipfile.ZipFile(filepath) as zf:
            for name in zf.namelist():
                lib_filename = os.path.basename(name)
                if lib_filename.endswith(".lib"):
                    bitness = ""
                    if "x86" in name:
                        bitness = "x86"
                    elif "x64" in name:
                        bitness = "x64"
                    content = zf.read(name)
                    output_filename = f"{family}_{regexed_version}_{msvc}_{bitness}_{lib_filename}"
                    extracted_lib_filepath = lib_basedir + os.sep + output_filename
                    extracted_lib_files.append(extracted_lib_filepath)
                    if not os.path.exists(extracted_lib_filepath):
                        with open(extracted_lib_filepath, "wb") as fout:
                            fout.write(content)
        return extracted_lib_files
    
    def ensureDirExists(self, filepath):
        """ Ensure that a given filepath exists as directory, creating it otherwise """
        try:
            os.makedirs(filepath)
            # give FS a moment to realize what's happening
            time.sleep(0.05)
        except:
            pass

    def ensureEmptyTmpDir(self, tmp_filepath=None):
        """ Ensure that a given filepath exists as directory, and that it is fully empty """
        if tmp_filepath is None:
            tmp_filepath = self.config.lib2smda_tmp_root + os.sep + "ar_output"
        if os.path.isdir(tmp_filepath):
            shutil.rmtree(tmp_filepath)
        elif os.path.isfile(tmp_filepath):
            os.remove(tmp_filepath)
        time.sleep(0.05)
        self.ensureDirExists(tmp_filepath)
        time.sleep(0.05)
        return tmp_filepath
