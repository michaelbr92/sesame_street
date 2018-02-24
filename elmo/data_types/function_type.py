import contextlib
from builtins import print
from typing import Dict, Union, List

from elmo.data_types.base_data_type import BaseDataType
from elmo.data_types.opcode_type import Opcode
from .. import r2


class Function(BaseDataType):

    VARIABLE_KIND = 'var'
    ARGUMENT_KIND = 'arg'

    def __init__(self, offset: int = None, name: str="", *args, **kwargs):
        """
        a wrapper over the r2 Function object

        @param offset: an offset to the function
        @param name: get the function by name
        """
        super().__init__(*args, **kwargs)
        if offset is not None:
            self.offset = offset
        elif name:
            cmd = f"afij {name}"
            self.offset = self.cmdj(cmd)[0]['offset']

    # todo: check if there is a better way to get the current seek address
    @contextlib.contextmanager
    def seek_function(self):
        """
        will get into the context of the function and return to the previous one

        @note this function uses the seek stack so any change on it inside the context will have unexpected result
        """
        inside_cmd = f"s 0x{self.offset:x}"
        outside_cmd = f"s-"

        self.cmd(inside_cmd)
        yield
        self.cmd(outside_cmd)

    def get_function_info(self) -> Dict[str, any]:
        """
        get the dictionary that represents all the info about this function
        @return: a dict of info
        """
        cmd = f"afij 0x{self.offset:x}"

        function_infos = [f for f in self.cmdj(cmd) if f["offset"] == self.offset]

        if len(function_infos) > 1:
            raise Exception("Found multiple functions with in this offset")

        function_info = function_infos[0]
        return function_info

    @property
    def name(self) -> str:
        """
        @return: the function name
        """
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

    def _args_and_variables(self) -> List[Dict[str, any]]:
        """
        @return: all the locals/arguments in the function
        """
        with self.seek_function():
            args_vars = self.cmdj("afvj")
        return args_vars['bp'] + args_vars['sp'] + args_vars['reg']

    def variables(self, raw: bool):
        """
        @param raw: will indicate it to return the variables in a raw way (json parsed dict)
        @return: all the variables (locals) in the function
        """
        if raw:
            return [var for var in self._args_and_variables() if var['kind'] == self.VARIABLE_KIND]
        else:
            raise NotImplementedError("Not yet implemented returning an object representing an argument/local")

    def print_opcodes(self):
        """
        print the function disassembled representation
        """
        for opcode in self.opcodes():
            if not opcode.is_valid():
                break
            print(opcode.disasm())
