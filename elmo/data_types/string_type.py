import base64
from typing import Dict

from elmo.data_types.base_data_type import BaseDataType


class String(BaseDataType):

    def __init__(self, string_dict: Dict[str, object], *args, **kwargs):
        """
        a representation of the string in radare

        @param _r2: the instance of the radare2
        @param string_dict: the dict returned from radare json command
        """
        super().__init__(*args, **kwargs)
        self.string_dict = string_dict

    @property
    def string(self) -> bytes:
        encoded_str = self.string_dict.get('string')
        return base64.b64decode(encoded_str)

    @string.setter
    def string(self, value):
        pass
