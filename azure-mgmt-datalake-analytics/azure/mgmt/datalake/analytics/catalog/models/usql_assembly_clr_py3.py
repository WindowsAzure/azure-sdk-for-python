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

from .catalog_item_py3 import CatalogItem


class USqlAssemblyClr(CatalogItem):
    """A Data Lake Analytics catalog U-SQL assembly CLR item.

    :param compute_account_name: the name of the Data Lake Analytics account.
    :type compute_account_name: str
    :param version: the version of the catalog item.
    :type version: str
    :param database_name: the name of the database.
    :type database_name: str
    :param name: the name of the assembly.
    :type name: str
    :param clr_name: the name of the CLR.
    :type clr_name: str
    """

    _attribute_map = {
        'compute_account_name': {'key': 'computeAccountName', 'type': 'str'},
        'version': {'key': 'version', 'type': 'str'},
        'database_name': {'key': 'databaseName', 'type': 'str'},
        'name': {'key': 'assemblyClrName', 'type': 'str'},
        'clr_name': {'key': 'clrName', 'type': 'str'},
    }

    def __init__(self, *, compute_account_name: str=None, version: str=None, database_name: str=None, name: str=None, clr_name: str=None, **kwargs) -> None:
        super(USqlAssemblyClr, self).__init__(compute_account_name=compute_account_name, version=version, **kwargs)
        self.database_name = database_name
        self.name = name
        self.clr_name = clr_name
