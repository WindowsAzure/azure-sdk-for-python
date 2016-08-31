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

from .catalog_item import CatalogItem


class USqlDatabase(CatalogItem):
    """A Data Lake Analytics catalog U-SQL database item.

    :param compute_account_name: the name of the Data Lake Analytics account.
    :type compute_account_name: str
    :param version: the version of the catalog item.
    :type version: str
    :param name: the name of the database.
    :type name: str
    """ 

    _attribute_map = {
        'compute_account_name': {'key': 'computeAccountName', 'type': 'str'},
        'version': {'key': 'version', 'type': 'str'},
        'name': {'key': 'databaseName', 'type': 'str'},
    }

    def __init__(self, compute_account_name=None, version=None, name=None):
        super(USqlDatabase, self).__init__(compute_account_name=compute_account_name, version=version)
        self.name = name
