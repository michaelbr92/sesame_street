from pprint import pprint
from typing import List
import re
import r2pipe

from elmo import data_types


class R2(r2pipe.open):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cmd('aa')

    def strings(self, search_query: str = "") -> 'List[data_types.String]':
        """

        @param search_query: an optional search key
        @warning search_query: the code might run slower if given search key
        @return: a list of string objects
        """
        all_strings = [data_types.String(offset=str_data['vaddr'], _r2=self)
                       for str_data in self.cmdj('izzj').get('strings')]

        if search_query:
            all_strings = [s for s in all_strings if re.match(f".*{search_query}.*", s.string)]

        return all_strings

    def functions(self) -> List[data_types.Function]:
        """
        get the functions
        @return: all the functions
        """
        all_functions = [data_types.Function(offset=int(offset, 16), _r2=self) for offset in self.cmdj('aflqj')]
        return all_functions
