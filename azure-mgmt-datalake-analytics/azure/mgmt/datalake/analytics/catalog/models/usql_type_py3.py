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


class USqlType(CatalogItem):
    """A Data Lake Analytics catalog U-SQL type item.

    :param compute_account_name: the name of the Data Lake Analytics account.
    :type compute_account_name: str
    :param version: the version of the catalog item.
    :type version: str
    :param database_name: the name of the database.
    :type database_name: str
    :param schema_name: the name of the schema associated with this table and
     database.
    :type schema_name: str
    :param name: the name of type for this type.
    :type name: str
    :param type_family: the type family for this type.
    :type type_family: str
    :param c_sharp_name: the C# name for this type.
    :type c_sharp_name: str
    :param full_csharp_name: the fully qualified C# name for this type.
    :type full_csharp_name: str
    :param system_type_id: the system type ID for this type.
    :type system_type_id: int
    :param user_type_id: the user type ID for this type.
    :type user_type_id: int
    :param schema_id: the schema ID for this type.
    :type schema_id: int
    :param principal_id: the principal ID for this type.
    :type principal_id: int
    :param is_nullable: the the switch indicating if this type is nullable.
    :type is_nullable: bool
    :param is_user_defined: the the switch indicating if this type is user
     defined.
    :type is_user_defined: bool
    :param is_assembly_type: the the switch indicating if this type is an
     assembly type.
    :type is_assembly_type: bool
    :param is_table_type: the the switch indicating if this type is a table
     type.
    :type is_table_type: bool
    :param is_complex_type: the the switch indicating if this type is a
     complex type.
    :type is_complex_type: bool
    """

    _attribute_map = {
        'compute_account_name': {'key': 'computeAccountName', 'type': 'str'},
        'version': {'key': 'version', 'type': 'str'},
        'database_name': {'key': 'databaseName', 'type': 'str'},
        'schema_name': {'key': 'schemaName', 'type': 'str'},
        'name': {'key': 'typeName', 'type': 'str'},
        'type_family': {'key': 'typeFamily', 'type': 'str'},
        'c_sharp_name': {'key': 'cSharpName', 'type': 'str'},
        'full_csharp_name': {'key': 'fullCSharpName', 'type': 'str'},
        'system_type_id': {'key': 'systemTypeId', 'type': 'int'},
        'user_type_id': {'key': 'userTypeId', 'type': 'int'},
        'schema_id': {'key': 'schemaId', 'type': 'int'},
        'principal_id': {'key': 'principalId', 'type': 'int'},
        'is_nullable': {'key': 'isNullable', 'type': 'bool'},
        'is_user_defined': {'key': 'isUserDefined', 'type': 'bool'},
        'is_assembly_type': {'key': 'isAssemblyType', 'type': 'bool'},
        'is_table_type': {'key': 'isTableType', 'type': 'bool'},
        'is_complex_type': {'key': 'isComplexType', 'type': 'bool'},
    }

    def __init__(self, *, compute_account_name: str=None, version: str=None, database_name: str=None, schema_name: str=None, name: str=None, type_family: str=None, c_sharp_name: str=None, full_csharp_name: str=None, system_type_id: int=None, user_type_id: int=None, schema_id: int=None, principal_id: int=None, is_nullable: bool=None, is_user_defined: bool=None, is_assembly_type: bool=None, is_table_type: bool=None, is_complex_type: bool=None, **kwargs) -> None:
        super(USqlType, self).__init__(compute_account_name=compute_account_name, version=version, **kwargs)
        self.database_name = database_name
        self.schema_name = schema_name
        self.name = name
        self.type_family = type_family
        self.c_sharp_name = c_sharp_name
        self.full_csharp_name = full_csharp_name
        self.system_type_id = system_type_id
        self.user_type_id = user_type_id
        self.schema_id = schema_id
        self.principal_id = principal_id
        self.is_nullable = is_nullable
        self.is_user_defined = is_user_defined
        self.is_assembly_type = is_assembly_type
        self.is_table_type = is_table_type
        self.is_complex_type = is_complex_type
