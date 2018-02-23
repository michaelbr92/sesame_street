from .. import r2


class BaseDataType(object):

    def __init__(self, _r2: 'r2.R2'):
        """
        basic commons between all data types

        @param _r2: the instance of radare2
        """
        self._r2 = _r2

    def cmd(self, *args, **kwargs):
        return self._r2.cmd(*args, **kwargs)

    def cmdj(self, *args, **kwargs):
        return self._r2.cmdj(*args, **kwargs)

