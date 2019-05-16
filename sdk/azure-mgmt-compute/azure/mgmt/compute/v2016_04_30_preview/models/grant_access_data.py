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


class GrantAccessData(Model):
    """Data used for requesting a SAS.

    All required parameters must be populated in order to send to Azure.

    :param access: Required. Possible values include: 'None', 'Read'
    :type access: str or
     ~azure.mgmt.compute.v2016_04_30_preview.models.AccessLevel
    :param duration_in_seconds: Required. Time duration in seconds until the
     SAS access expires.
    :type duration_in_seconds: int
    """

    _validation = {
        'access': {'required': True},
        'duration_in_seconds': {'required': True},
    }

    _attribute_map = {
        'access': {'key': 'access', 'type': 'AccessLevel'},
        'duration_in_seconds': {'key': 'durationInSeconds', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(GrantAccessData, self).__init__(**kwargs)
        self.access = kwargs.get('access', None)
        self.duration_in_seconds = kwargs.get('duration_in_seconds', None)
