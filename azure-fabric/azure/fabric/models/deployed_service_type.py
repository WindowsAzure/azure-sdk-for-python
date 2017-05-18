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


class DeployedServiceType(Model):
    """The type of the deploye service.

    :param service_type_name:
    :type service_type_name: str
    :param code_package_name:
    :type code_package_name: str
    :param service_manifest_name:
    :type service_manifest_name: str
    :param status:
    :type status: str
    """

    _attribute_map = {
        'service_type_name': {'key': 'ServiceTypeName', 'type': 'str'},
        'code_package_name': {'key': 'CodePackageName', 'type': 'str'},
        'service_manifest_name': {'key': 'ServiceManifestName', 'type': 'str'},
        'status': {'key': 'Status', 'type': 'str'},
    }

    def __init__(self, service_type_name=None, code_package_name=None, service_manifest_name=None, status=None):
        self.service_type_name = service_type_name
        self.code_package_name = code_package_name
        self.service_manifest_name = service_manifest_name
        self.status = status
