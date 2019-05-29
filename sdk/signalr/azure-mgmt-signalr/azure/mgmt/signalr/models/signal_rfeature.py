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


class SignalRFeature(Model):
    """Feature of a SignalR resource, which controls the SignalR runtime behavior.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar flag: Required. Kind of feature. Required. Default value:
     "ServiceMode" .
    :vartype flag: str
    :param value: Required. Value of the feature flag. See Azure SignalR
     service document https://docs.microsoft.com/en-us/azure/azure-signalr/ for
     allowed values.
    :type value: str
    :param properties: Optional properties related to this feature.
    :type properties: dict[str, str]
    """

    _validation = {
        'flag': {'required': True, 'constant': True},
        'value': {'required': True, 'max_length': 128, 'min_length': 1},
    }

    _attribute_map = {
        'flag': {'key': 'flag', 'type': 'str'},
        'value': {'key': 'value', 'type': 'str'},
        'properties': {'key': 'properties', 'type': '{str}'},
    }

    flag = "ServiceMode"

    def __init__(self, **kwargs):
        super(SignalRFeature, self).__init__(**kwargs)
        self.value = kwargs.get('value', None)
        self.properties = kwargs.get('properties', None)
