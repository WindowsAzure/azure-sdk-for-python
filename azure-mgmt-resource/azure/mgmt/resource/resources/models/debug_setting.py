# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class DebugSetting(Model):
    """DebugSetting

    :param detail_level: Gets or sets the debug detail level.
    :type detail_level: str
    """ 

    _attribute_map = {
        'detail_level': {'key': 'detailLevel', 'type': 'str'},
    }

    def __init__(self, detail_level=None):
        self.detail_level = detail_level
