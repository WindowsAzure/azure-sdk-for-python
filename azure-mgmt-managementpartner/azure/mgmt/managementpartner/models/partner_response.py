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


class PartnerResponse(Model):
    """this is the management partner operations response.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param etag: Type of the partner
    :type etag: int
    :ivar id: Identifier of the partner
    :vartype id: str
    :ivar name: Name of the partner
    :vartype name: str
    :param partner_id: This is the partner id
    :type partner_id: str
    :param partner_name: This is the partner name
    :type partner_name: str
    :param tenant_id: This is the tenant id.
    :type tenant_id: str
    :param object_id: This is the object id.
    :type object_id: str
    :param version: This is the version.
    :type version: str
    :param updated_time: This is the DateTime when the partner was updated.
    :type updated_time: datetime
    :param created_time: This is the DateTime when the partner was created.
    :type created_time: datetime
    :param state: This is the partner state. Possible values include:
     'Active', 'Deleted'
    :type state: str or ~azure.mgmt.managementpartner.models.enum
    :ivar type: Type of resource. "Microsoft.ManagementPartner/partners"
    :vartype type: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'etag': {'key': 'etag', 'type': 'int'},
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'partner_id': {'key': 'properties.partnerId', 'type': 'str'},
        'partner_name': {'key': 'properties.partnerName', 'type': 'str'},
        'tenant_id': {'key': 'properties.tenantId', 'type': 'str'},
        'object_id': {'key': 'properties.objectId', 'type': 'str'},
        'version': {'key': 'properties.version', 'type': 'str'},
        'updated_time': {'key': 'properties.updatedTime', 'type': 'iso-8601'},
        'created_time': {'key': 'properties.createdTime', 'type': 'iso-8601'},
        'state': {'key': 'properties.state', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(PartnerResponse, self).__init__(**kwargs)
        self.etag = kwargs.get('etag', None)
        self.id = None
        self.name = None
        self.partner_id = kwargs.get('partner_id', None)
        self.partner_name = kwargs.get('partner_name', None)
        self.tenant_id = kwargs.get('tenant_id', None)
        self.object_id = kwargs.get('object_id', None)
        self.version = kwargs.get('version', None)
        self.updated_time = kwargs.get('updated_time', None)
        self.created_time = kwargs.get('created_time', None)
        self.state = kwargs.get('state', None)
        self.type = None
