import os
import time

import config

def ensure_dir(filepath):
    try:
        os.makedirs(filepath)
        # give FS a moment to realize what's happening
        time.sleep(0.2)
    except:
        pass


def ensure_empty_tmp_dir(tmp_filepath=None):
    if tmp_filepath is None:
        tmp_filepath = config.LIB2SMDA_TMP_ROOT + os.sep + "ar_output"
    ensure_dir(tmp_filepath)
    for filename in os.listdir(tmp_filepath):
        os.remove(tmp_filepath + os.sep + filename)
    time.sleep(0.2)
    return tmp_filepath


def extract_lib_files(filepath):
    """
    In case our libfiles are nested somehow in a zip file, we can also extract that one first
    """
    regex_version = r"(?P<version>\d+\.\d+(\.\d+)*(\-\d+)?([a-z])?)"
    extracted_lib_files = []
    pack_basedir = os.path.dirname(filepath)[:-4]
    lib_basedir = pack_basedir + os.sep + "lib"
    ensure_dir(lib_basedir)
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