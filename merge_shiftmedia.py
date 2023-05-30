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


if __name__ == "__main__":
    this_path = str(os.path.abspath(os.sep.join([str(os.path.abspath(__file__)), ".."])))
    ida_interact = os.sep.join([this_path, "ida_interact.py"])
    lib2smda_config = Lib2SmdaConfig(this_path, config.LIB2SMDA_TMP_ROOT, ida_interact, config.IDA_ROOT)
    input_filepath = os.path.abspath(sys.argv[1])
    # initialize converter
    converter = Lib2SmdaConverter(lib2smda_config)
    sha256_by_libfile = {}
    smda_files_by_dirname = {}
    for root, dirs, files in sorted(os.walk(sys.argv[1], topdown=False)):
        for filename in sorted(files):
            filepath = os.path.abspath(root + os.sep + filename)
            lib_dirname = os.path.dirname(filepath)
            if filepath.endswith(".lib"):
                file_sha256 = ""
                with open(filepath, "rb") as fin:
                    sha256_by_libfile[os.path.basename(filepath)] = hashlib.sha256(fin.read()).hexdigest()
            if filepath.endswith(".smda"):
                if os.path.dirname(filepath) not in smda_files_by_dirname:
                    smda_files_by_dirname[os.path.dirname(filepath)] = []
                smda_files_by_dirname[os.path.dirname(filepath)].append(os.path.basename(filepath))
    print(f"Located {len(sha256_by_libfile)} libfiles, with a total of {sum([len(basenames) for basenames in smda_files_by_dirname.values()])} SMDA reports.")
    num_total_functions = 0
    for dirname, basenames in tqdm(smda_files_by_dirname.items()):
        lib_identifier = dirname.rsplit(os.sep, 1)[-1]
        smda_reports = []
        if lib_identifier + ".lib" in sha256_by_libfile:
            for basename in basenames:
                smda_report = SmdaReport.fromFile(dirname + os.sep + basename)
                smda_reports.append(smda_report)
            if smda_reports:
                merged_report = converter.mergeSmdaReports(smda_reports)
                if merged_report:
                    merged_report.sha256 = sha256_by_libfile[lib_identifier + ".lib"]
                    merged_report.filename = os.path.basename(lib_identifier + ".lib")
                    merged_report.component = ""
                    num_total_functions += merged_report.statistics.num_functions
                    with open(sys.argv[2] + os.sep + lib_identifier + ".smda", "w") as fout:
                        json.dump(merged_report.toDict(), fout, indent=1, sort_keys=True)
    print(f"Across all SMDA reports, found {num_total_functions} functions.")
