# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class SkuCapacity(Model):
    """
    Description of the App Service Plan scale options

    :param minimum: Minimum number of Workers for this App Service Plan SKU
    :type minimum: int
    :param maximum: Maximum number of Workers for this App Service Plan SKU
    :type maximum: int
    :param default: Default number of Workers for this App Service Plan SKU
    :type default: int
    :param scale_type: Available scale configurations for an App Service Plan
    :type scale_type: str
    """ 

    _attribute_map = {
        'minimum': {'key': 'minimum', 'type': 'int'},
        'maximum': {'key': 'maximum', 'type': 'int'},
        'default': {'key': 'default', 'type': 'int'},
        'scale_type': {'key': 'scaleType', 'type': 'str'},
    }

    def __init__(self, minimum=None, maximum=None, default=None, scale_type=None):
        self.minimum = minimum
        self.maximum = maximum
        self.default = default
        self.scale_type = scale_type
