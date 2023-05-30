import os

class Lib2SmdaConfig(object):

    def __init__(self, project_root, tmp_root, ida_interact_path, ida_root) -> None:
        self.project_root = str(os.path.abspath(project_root))
        self.lib2smda_tmp_root = str(os.path.abspath(tmp_root))
        self.ida_interact_path = ida_interact_path
        self.ida_root = str(os.path.abspath(ida_root))
        self.ida32_path = os.sep.join([self.ida_root, "idat"])
        self.ida64_path = os.sep.join([self.ida_root, "idat64"])

    def __str__(self):
        return f"Project Root: {self.project_root}, Temp Root: {self.lib2smda_tmp_root}, IDA Interact: {self.ida_interact_path}, IDA Root: {self.ida_root}"