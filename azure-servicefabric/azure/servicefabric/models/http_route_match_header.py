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


class HttpRouteMatchHeader(Model):
    """Describes header information for http route matching.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. Name of header to match in request.
    :type name: str
    :param value: Value of header to match in request.
    :type value: str
    :param type: how to match header value. Possible values include: 'exact'
    :type type: str or ~azure.servicefabric.models.HeaderMatchType
    """

    _validation = {
        'name': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'value': {'key': 'value', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(HttpRouteMatchHeader, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.value = kwargs.get('value', None)
        self.type = kwargs.get('type', None)
