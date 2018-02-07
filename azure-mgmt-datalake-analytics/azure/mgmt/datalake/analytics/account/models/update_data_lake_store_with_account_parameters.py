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


class UpdateDataLakeStoreWithAccountParameters(Model):
    """The parameters used to update a Data Lake Store account while updating a
    Data Lake Analytics account.

    :param name: The unique name of the Data Lake Store account to update.
    :type name: str
    :param suffix: The optional suffix for the Data Lake Store account.
    :type suffix: str
    """

    _validation = {
        'name': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'suffix': {'key': 'properties.suffix', 'type': 'str'},
    }

    def __init__(self, name, suffix=None):
        super(UpdateDataLakeStoreWithAccountParameters, self).__init__()
        self.name = name
        self.suffix = suffix
