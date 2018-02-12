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


class ClusterCodeVersionsResult(Model):
    """The result of the ServiceFabric runtime versions.

    :param id: The identification of the result
    :type id: str
    :param name: The name of the result
    :type name: str
    :param type: The result resource type
    :type type: str
    :param code_version: The Service Fabric runtime version of the cluster.
    :type code_version: str
    :param support_expiry_utc: The date of expiry of support of the version.
    :type support_expiry_utc: str
    :param environment: Indicates if this version is for Windows or Linux
     operating system. Possible values include: 'Windows', 'Linux'
    :type environment: str or ~azure.mgmt.servicefabric.models.enum
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'code_version': {'key': 'properties.codeVersion', 'type': 'str'},
        'support_expiry_utc': {'key': 'properties.supportExpiryUtc', 'type': 'str'},
        'environment': {'key': 'properties.environment', 'type': 'str'},
    }

    def __init__(self, id=None, name=None, type=None, code_version=None, support_expiry_utc=None, environment=None):
        super(ClusterCodeVersionsResult, self).__init__()
        self.id = id
        self.name = name
        self.type = type
        self.code_version = code_version
        self.support_expiry_utc = support_expiry_utc
        self.environment = environment
