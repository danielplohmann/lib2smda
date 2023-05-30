import os
import json
import traceback

import idc
import idaapi
import ida_auto
import ida_pro

from smda.Disassembler import Disassembler
from smda.ida.IdaInterface import IdaInterface


if idaapi.IDA_SDK_VERSION < 740:
    raise Exception("This script has been only tested for IDA_SDK_VERSION 7.4 and above.")

this_path = str(os.path.abspath(os.sep.join([str(os.path.abspath(__file__)), ".."])))
smda_output_dir = os.sep.join([this_path, "converter_tmp", "ida_output"])
smda_report_output_path = os.sep.join([smda_output_dir, "ida_output_converted.json"])
try:
    input_filepath = idc.get_input_file_path()
    ida_auto.auto_wait()
    ida_interface = IdaInterface()
    binary = ida_interface.getBinary()
    base_addr = ida_interface.getBaseAddr()
    DISASSEMBLER = Disassembler(backend="IDA")
    REPORT = DISASSEMBLER.disassembleBuffer(binary, base_addr)
    output_path = ida_interface.getIdbDir()
    with open(smda_report_output_path, "w") as fout:
        json.dump(REPORT.toDict(), fout, indent=1, sort_keys=True)
except Exception as exc:
    with open(smda_report_output_path + ".error", "w") as fout:
        fout.write(input_filepath)
        fout.write(traceback.format_exc())
ida_pro.qexit(0)
