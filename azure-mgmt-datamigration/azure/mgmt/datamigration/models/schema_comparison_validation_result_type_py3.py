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


class SchemaComparisonValidationResultType(Model):
    """Description about the errors happen while performing migration validation.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar object_name: Name of the object that has the difference
    :vartype object_name: str
    :ivar object_type: Type of the object that has the difference. e.g
     (Table/View/StoredProcedure). Possible values include: 'StoredProcedures',
     'Table', 'User', 'View', 'Function'
    :vartype object_type: str or ~azure.mgmt.datamigration.models.ObjectType
    :ivar update_action: Update action type with respect to target. Possible
     values include: 'DeletedOnTarget', 'ChangedOnTarget', 'AddedOnTarget'
    :vartype update_action: str or
     ~azure.mgmt.datamigration.models.UpdateActionType
    """

    _validation = {
        'object_name': {'readonly': True},
        'object_type': {'readonly': True},
        'update_action': {'readonly': True},
    }

    _attribute_map = {
        'object_name': {'key': 'objectName', 'type': 'str'},
        'object_type': {'key': 'objectType', 'type': 'str'},
        'update_action': {'key': 'updateAction', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(SchemaComparisonValidationResultType, self).__init__(**kwargs)
        self.object_name = None
        self.object_type = None
        self.update_action = None
