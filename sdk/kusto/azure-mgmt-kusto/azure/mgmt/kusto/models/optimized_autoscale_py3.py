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


class OptimizedAutoscale(Model):
    """A class that contains the optimized auto scale definition.

    All required parameters must be populated in order to send to Azure.

    :param version: Required. The version of the template defined, for
     instance 1.
    :type version: int
    :param is_enabled: Required. A boolean value that indicate if the
     optimized autoscale feature is enabled or not.
    :type is_enabled: bool
    :param minimum: Required. Minimum allowed instances count.
    :type minimum: int
    :param maximum: Required. Maximum allowed instances count.
    :type maximum: int
    """

    _validation = {
        'version': {'required': True},
        'is_enabled': {'required': True},
        'minimum': {'required': True},
        'maximum': {'required': True},
    }

    _attribute_map = {
        'version': {'key': 'version', 'type': 'int'},
        'is_enabled': {'key': 'isEnabled', 'type': 'bool'},
        'minimum': {'key': 'minimum', 'type': 'int'},
        'maximum': {'key': 'maximum', 'type': 'int'},
    }

    def __init__(self, *, version: int, is_enabled: bool, minimum: int, maximum: int, **kwargs) -> None:
        super(OptimizedAutoscale, self).__init__(**kwargs)
        self.version = version
        self.is_enabled = is_enabled
        self.minimum = minimum
        self.maximum = maximum
