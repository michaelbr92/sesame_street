import base64
from typing import Dict

from elmo.data_types.base_data_type import BaseDataType


class String(BaseDataType):

    def __init__(self, offset: int, *args, **kwargs):
        """
        a representation of the string in radare

        @param _r2: the instance of the radare2
        @param string_dict: the dict returned from radare json command
        """
        super().__init__(*args, **kwargs)
        self.offset = offset

    @property
    def string(self) -> bytes:
        cmd = f"pfj z @0x{self.offset:x}"
        found_strings = self.cmdj(cmd)
        if found_strings != 1:
            raise Exception(f"Expected 1 string at 0x{self.offset:x} got {len(found_strings)}")

        return found_strings[0]["string"]

    @string.setter
    def string(self, value):
        raise NotImplementedError("Overwriting strings not yet implemented")
