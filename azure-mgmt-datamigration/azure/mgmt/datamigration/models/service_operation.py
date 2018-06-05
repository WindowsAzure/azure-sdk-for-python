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


class ServiceOperation(Model):
    """Description of an action supported by the Database Migration Service.

    :param name: The fully qualified action name, e.g.
     Microsoft.DataMigration/services/read
    :type name: str
    :param display: Localized display text
    :type display: ~azure.mgmt.datamigration.models.ServiceOperationDisplay
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display': {'key': 'display', 'type': 'ServiceOperationDisplay'},
    }

    def __init__(self, **kwargs):
        super(ServiceOperation, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.display = kwargs.get('display', None)
