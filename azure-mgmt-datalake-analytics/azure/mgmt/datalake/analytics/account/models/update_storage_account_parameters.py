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


class UpdateStorageAccountParameters(Model):
    """The parameters used to update an Azure Storage account.

    :param access_key: The updated access key associated with this Azure
     Storage account that will be used to connect to it.
    :type access_key: str
    :param suffix: The optional suffix for the storage account.
    :type suffix: str
    """

    _attribute_map = {
        'access_key': {'key': 'properties.accessKey', 'type': 'str'},
        'suffix': {'key': 'properties.suffix', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(UpdateStorageAccountParameters, self).__init__(**kwargs)
        self.access_key = kwargs.get('access_key', None)
        self.suffix = kwargs.get('suffix', None)
