# Apply function signature from MiniDebugInfo. Requires eu-readelf from elfutils.
#@author Olivier Le Moal
#@category FunctionID
#@menupath Tools.Function ID.MiniDebugInfo

import subprocess
import sys
import os.path
from ghidra.program.model.symbol import SourceType

path_binary = currentProgram.executablePath
functionManager = currentProgram.getFunctionManager()
addressFactory = currentProgram.getAddressFactory()

if not os.path.isfile(path_binary):
    print("Can't find file : {}".format(path_binary))
    sys.exit(1)

process = subprocess.Popen(['eu-readelf', '-Ws', '--elf-section', path_binary], stdout=subprocess.PIPE)
stdout = process.communicate()[0].splitlines()

for l in stdout[4:]:
    fields = l.split()
    if fields[3] == "FUNC":
        address = addressFactory.getAddress(fields[1])
        func_name = fields[7]
        f = functionManager.getFunctionAt(address)
        if f:
            print("Function {} found at {}".format(func_name, address))
            f.setName(func_name, SourceType.USER_DEFINED)
        else:
            print("No function found at {} ({})".format(address, func_name))


