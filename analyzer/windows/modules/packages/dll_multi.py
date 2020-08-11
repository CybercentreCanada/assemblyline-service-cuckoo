# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file was originally part of Cuckoo Sandbox - http://www.cuckoosandbox.org (https://github.com/cuckoosandbox/cuckoo)
# Copied and modified for use within AssemblyLine

import os
import shlex
import shutil

from lib.common.abstracts import Package

class DllMulti(Package):
    """DLL analysis package, for attempting to execute multiple exports"""
    PATHS = [
        ("System32", "rundll32.exe"),
    ]

    def start(self, path):
        rundll32 = self.get_path("rundll32.exe")
        functions = self.options.get("function", "DllMain").split("|")
        arguments = self.options.get("arguments", "")
        loader_name = self.options.get("loader")

        # Check file extension.
        ext = os.path.splitext(path)[-1].lower()

        # If the file doesn't have the proper .dll extension force it
        # and rename it. This is needed for rundll32 to execute correctly.
        # See ticket #354 for details.
        if ext != ".dll":
            new_path = path + ".dll"
            os.rename(path, new_path)
            path = new_path

        if loader_name:
            loader = os.path.join(os.path.dirname(rundll32), loader_name)
            shutil.copy(rundll32, loader)
            rundll32 = loader

        ret_list = []
        for function_name in functions:
            args = ["%s,%s" % (path, function_name)]
            if arguments:
                args += shlex.split(arguments)

            ret_list.append(self.execute(rundll32, args=args))

        return ret_list
