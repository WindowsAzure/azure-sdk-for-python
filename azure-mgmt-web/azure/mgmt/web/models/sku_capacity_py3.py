# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class SkuCapacity(Model):
    """Description of the App Service plan scale options.

    :param minimum: Minimum number of workers for this App Service plan SKU.
    :type minimum: int
    :param maximum: Maximum number of workers for this App Service plan SKU.
    :type maximum: int
    :param default: Default number of workers for this App Service plan SKU.
    :type default: int
    :param scale_type: Available scale configurations for an App Service plan.
    :type scale_type: str
    """

    _attribute_map = {
        'minimum': {'key': 'minimum', 'type': 'int'},
        'maximum': {'key': 'maximum', 'type': 'int'},
        'default': {'key': 'default', 'type': 'int'},
        'scale_type': {'key': 'scaleType', 'type': 'str'},
    }

    def __init__(self, *, minimum: int=None, maximum: int=None, default: int=None, scale_type: str=None, **kwargs) -> None:
        super(SkuCapacity, self).__init__(**kwargs)
        self.minimum = minimum
        self.maximum = maximum
        self.default = default
        self.scale_type = scale_type
