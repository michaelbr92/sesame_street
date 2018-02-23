from builtins import print
from typing import Dict

from elmo.data_types.base_data_type import BaseDataType
from .. import r2


class Function(BaseDataType):

    def __init__(self, function_dict: Dict[str, object], *args, **kwargs):
        """
        a wrapper over the r2 Function object
        :param _r2: the r2 instance
        :param function_dict: a function json dict returned from radar2
        """
        super().__init__(*args, **kwargs)
        self._function_dict = function_dict

        self._name = function_dict.get('name', 'unknown?')
        self.offset = function_dict.get('offset', 0)

    def get_function_info(self):
        cmd = f"afij 0x{self.offset:x}"

        function_infos = [f for f in self.cmdj(cmd) if f["offset"] == self.offset]
        if len(function_infos) > 1:
            raise Exception("Found multiple functions with in this offset")
        function_info = function_infos[0]
        return function_info

    @property
    def name(self):
        function_info = self.get_function_info()
        return function_info['name']

    @name.setter
    def name(self, new_name):
        cmd = f"afn {new_name} @0x{self.offset:x}"
        self.cmd(cmd)

    def print_opcodes(self):
        """
        print the function disassembled representation
        """
        for opcode in self.cmdj('pdfj @ {}'.format(hex(self.offset)))['ops']:
            if opcode['type'] == 'invalid':
                break
            print(opcode['disasm'])
