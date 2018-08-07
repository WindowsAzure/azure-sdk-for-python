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


class ContainerHttpGet(Model):
    """The container Http Get settings, for liveness or readiness probe.

    All required parameters must be populated in order to send to Azure.

    :param path: The path to probe.
    :type path: str
    :param port: Required. The port number to probe.
    :type port: int
    :param scheme: The scheme. Possible values include: 'http', 'https'
    :type scheme: str or ~azure.mgmt.containerinstance.models.enum
    """

    _validation = {
        'port': {'required': True},
    }

    _attribute_map = {
        'path': {'key': 'path', 'type': 'str'},
        'port': {'key': 'port', 'type': 'int'},
        'scheme': {'key': 'scheme', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ContainerHttpGet, self).__init__(**kwargs)
        self.path = kwargs.get('path', None)
        self.port = kwargs.get('port', None)
        self.scheme = kwargs.get('scheme', None)
