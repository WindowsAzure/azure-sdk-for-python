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


class DeleteRetentionPolicy(Model):
    """The blob service properties for soft delete.

    :param enabled: Indicates whether DeleteRetentionPolicy is enabled for the
     Blob service.
    :type enabled: bool
    :param days: Indicates the number of days that the deleted blob should be
     retained. The minimum specified value can be 1 and the maximum value can
     be 365.
    :type days: int
    """

    _validation = {
        'days': {'maximum': 365, 'minimum': 1},
    }

    _attribute_map = {
        'enabled': {'key': 'enabled', 'type': 'bool'},
        'days': {'key': 'days', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(DeleteRetentionPolicy, self).__init__(**kwargs)
        self.enabled = kwargs.get('enabled', None)
        self.days = kwargs.get('days', None)
