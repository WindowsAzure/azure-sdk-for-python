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


class ApplicationSummary(Model):
    """Contains information about an application in an Azure Batch account.

    All required parameters must be populated in order to send to Azure.

    :param id: Required. A string that uniquely identifies the application
     within the account.
    :type id: str
    :param display_name: Required. The display name for the application.
    :type display_name: str
    :param versions: Required. The list of available versions of the
     application.
    :type versions: list[str]
    """

    _validation = {
        'id': {'required': True},
        'display_name': {'required': True},
        'versions': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'versions': {'key': 'versions', 'type': '[str]'},
    }

    def __init__(self, **kwargs):
        super(ApplicationSummary, self).__init__(**kwargs)
        self.id = kwargs.get('id', None)
        self.display_name = kwargs.get('display_name', None)
        self.versions = kwargs.get('versions', None)
