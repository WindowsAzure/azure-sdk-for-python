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


class ServiceDescriptionTemplate(Model):
    """The template of the service description.

    :param service_name:
    :type service_name: str
    :param service_type_name:
    :type service_type_name: str
    """

    _attribute_map = {
        'service_name': {'key': 'ServiceName', 'type': 'str'},
        'service_type_name': {'key': 'ServiceTypeName', 'type': 'str'},
    }

    def __init__(self, service_name=None, service_type_name=None):
        self.service_name = service_name
        self.service_type_name = service_type_name
