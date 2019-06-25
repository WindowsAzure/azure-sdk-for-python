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


class UpdateWorkspaceQuotas(Model):
    """The properties for update Quota response.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Specifies the resource ID.
    :vartype id: str
    :ivar type: Specifies the resource type.
    :vartype type: str
    :param limit: Limit. The maximum permitted quota of the resource.
    :type limit: long
    :ivar unit: An enum describing the unit of quota measurement. Possible
     values include: 'Count'
    :vartype unit: str or ~azure.mgmt.machinelearningservices.models.QuotaUnit
    :param status: Update Workspace Quota Status. Status of update workspace
     quota. Possible values include: 'Undefined', 'Success', 'Failure'
    :type status: str or ~azure.mgmt.machinelearningservices.models.Status
    """

    _validation = {
        'id': {'readonly': True},
        'type': {'readonly': True},
        'unit': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'limit': {'key': 'limit', 'type': 'long'},
        'unit': {'key': 'unit', 'type': 'str'},
        'status': {'key': 'status', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(UpdateWorkspaceQuotas, self).__init__(**kwargs)
        self.id = None
        self.type = None
        self.limit = kwargs.get('limit', None)
        self.unit = None
        self.status = kwargs.get('status', None)
