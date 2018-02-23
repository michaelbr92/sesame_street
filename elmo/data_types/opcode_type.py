from typing import Dict

from elmo.data_types.base_data_type import BaseDataType


class Opcode(BaseDataType):

    def __init__(self, offset: int, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.offset = offset

    def _get_opcode_data(self) -> Dict[str, ]:
        cmd = f"pdj 1 @0x{self.offset:x}"
        opcodes_data = self.cmdj(cmd)

        if len(opcodes_data) > 1:
            raise ValueError(f"Too many opcodes in at address 0x{self.offset}")

        return opcodes_data[0]

    def is_valid(self) -> bool:
        return self._get_opcode_data().get('type') != 'invalid'

    def type(self) -> str:
        return self._get_opcode_data().get('type')

    def disasm(self) -> str:
        return self._get_opcode_data().get('disasm')
