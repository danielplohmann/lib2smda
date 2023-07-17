import os
import sys
import json
from collections import Counter
from copy import deepcopy

from smda.common.SmdaReport import SmdaReport



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


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <path_to_smda_folder> <opt:family> <opt:version>")
        sys.exit(1)
    if not os.path.isdir(sys.argv[1]):
        print(f"path {sys.argv[1]} is not a directory")
        sys.exit(2)
    input_path = os.path.abspath(sys.argv[1])
    function_counts = Counter()
    # unpack lib file into obj
    num_functions = 0
    smda_reports = []
    for filename in os.listdir(input_path):
        smda_report = SmdaReport.fromFile(input_path + os.sep + filename)
        print(smda_report)
        smda_reports.append(smda_report)

    merged_report = merge_reports(smda_reports)
    if merged_report:
        merged_report.filename = os.path.dirname(input_path)
    with open(input_path + ".smda", "w") as fout:
        json.dump(merged_report.toDict(), fout, indent=1, sort_keys=True)
