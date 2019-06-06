import unittest
import pytest
import azure.cosmos.diagnostics as m

_common = {
    'x-ms-activity-id',
    'x-ms-request-charge',
    'x-ms-session-token',

    'x-ms-item-count',
    'x-ms-request-quota',
    'x-ms-resource-usage',
    'x-ms-retry-after-ms',
}

_headers = dict(zip(_common, _common))
_headers['other'] = 'other'

class BaseUnitTests(unittest.TestCase):

    def test_init(self):
        rh = m.RecordHeaders()
        assert rh.headers == {}

    def test_headers(self):
        rh = m.RecordHeaders()
        rh(_headers)
        assert rh.headers == _headers
        assert rh.headers is not _headers

    def test_common_attrs(self):
        rh = m.RecordHeaders()
        rh(_headers)
        for name in _common:
            assert rh.headers[name] == name
            attr = name.replace('x-ms-', '').replace('-', '_')
            assert getattr(rh, attr) == name

    def test_other_attrs(self):
        rh = m.RecordHeaders()
        rh(_headers)
        assert rh.headers['other'] == 'other'
        with pytest.raises(AttributeError):
            rh.other
