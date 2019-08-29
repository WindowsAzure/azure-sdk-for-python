import sys

if sys.version_info < (3,):
    def _str(value):
        if isinstance(value, unicode):  # pylint: disable=undefined-variable
            return value.encode('utf-8')

        return str(value)
else:
    _str = str


def _to_utc_datetime(value):
    return value.strftime('%Y-%m-%dT%H:%M:%SZ')
