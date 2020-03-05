# Apply function signature from MiniDebugInfo. Requires eu-readelf from elfutils.
#@author Olivier Le Moal
#@category FunctionID
#@menupath Tools.Function ID.MiniDebugInfo

from ghidra.program.model.symbol import SourceType
import subprocess

path = currentProgram.executablePath
functionManager = currentProgram.getFunctionManager()
addressFactory = currentProgram.getAddressFactory()

process = subprocess.Popen(['eu-readelf', '-Ws', '--elf-section', path], stdout=subprocess.PIPE)
stdout = process.communicate()[0].splitlines()

for l in stdout[4:]:
    fields = l.split()
    if fields[3] == "FUNC":
        address = addressFactory.getAddress(fields[1])
        func_name = fields[7]
        f = functionManager.getFunctionAt(address)
        if f:
            f.setName(func_name, SourceType.USER_DEFINED)
        else:
            print("No function found at {} ({})".format(address, func_name))


