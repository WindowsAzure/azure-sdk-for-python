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


class USqlAssemblyDependencyInfo(Model):
    """A Data Lake Analytics catalog U-SQL dependency information item.

    :param entity_id: the EntityId of the dependency.
    :type entity_id: ~azure.mgmt.datalake.analytics.catalog.models.EntityId
    """

    _attribute_map = {
        'entity_id': {'key': 'entityId', 'type': 'EntityId'},
    }

    def __init__(self, *, entity_id=None, **kwargs) -> None:
        super(USqlAssemblyDependencyInfo, self).__init__(**kwargs)
        self.entity_id = entity_id
