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


class SsisObjectMetadata(Model):
    """SSIS object metadata.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: SsisEnvironment, SsisPackage, SsisProject, SsisFolder

    All required parameters must be populated in order to send to Azure.

    :param id: Metadata id.
    :type id: long
    :param name: Metadata name.
    :type name: str
    :param description: Metadata description.
    :type description: str
    :param type: Required. Constant filled by server.
    :type type: str
    """

    _validation = {
        'type': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'long'},
        'name': {'key': 'name', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    _subtype_map = {
        'type': {'Environment': 'SsisEnvironment', 'Package': 'SsisPackage', 'Project': 'SsisProject', 'Folder': 'SsisFolder'}
    }

    def __init__(self, *, id: int=None, name: str=None, description: str=None, **kwargs) -> None:
        super(SsisObjectMetadata, self).__init__(**kwargs)
        self.id = id
        self.name = name
        self.description = description
        self.type = None
