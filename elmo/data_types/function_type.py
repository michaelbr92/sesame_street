from builtins import print
from typing import Dict, Union, List

from elmo.data_types.base_data_type import BaseDataType
from elmo.data_types.opcode_type import Opcode
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

    def get_function_info(self) -> Dict[str, ]:
        """
        get the dictionary that represents all the info about this function
        @return: a dict of info
        """
        cmd = f"afij 0x{self.offset:x}"
        print(cmd)

        function_infos = [f for f in self.cmdj(cmd) if f["offset"] == self.offset]

        if len(function_infos) > 1:
            raise Exception("Found multiple functions with in this offset")

        function_info = function_infos[0]
        return function_info

    @property
    def name(self) -> str:
        function_info = self.get_function_info()
        return function_info['name']

    @name.setter
    def name(self, new_name: str) -> None:
        """
        will set a new name to the function ( updating radare )
        @param new_name: the new name for the function
        """
        cmd = f"afn {new_name} @0x{self.offset:x}"
        self.cmd(cmd)

    def opcodes(self) -> List[Opcode]:
        """
        @return: list of op code objects for the function
        """
        cmd = f"pdfj @0x{self.offset:x}"
        opcodes_data = self.cmdj(cmd)['ops']
        opcodes = [Opcode(op['offset'], _r2=self._r2) for op in opcodes_data]
        return opcodes

    def print_opcodes(self):
        """
        print the function disassembled representation
        """
        for opcode in self.opcodes():
            if not opcode.is_valid():
                break
            print(opcode.disasm())
