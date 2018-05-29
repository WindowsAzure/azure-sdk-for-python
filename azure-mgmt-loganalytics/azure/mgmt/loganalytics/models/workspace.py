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

from .resource import Resource


class Workspace(Resource):
    """The top level Workspace resource container.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id
    :vartype id: str
    :ivar name: Resource name
    :vartype name: str
    :ivar type: Resource type
    :vartype type: str
    :param location: Resource location
    :type location: str
    :param tags: Resource tags
    :type tags: dict[str, str]
    :param provisioning_state: The provisioning state of the workspace.
     Possible values include: 'Creating', 'Succeeded', 'Failed', 'Canceled',
     'Deleting', 'ProvisioningAccount'
    :type provisioning_state: str or
     ~azure.mgmt.loganalytics.models.EntityStatus
    :param source: The source of the workspace.  Source defines where the
     workspace was created. 'Azure' implies it was created in Azure.
     'External' implies it was created via the Operational Insights Portal.
     This value is set on the service side and read-only on the client side.
    :type source: str
    :param customer_id: The ID associated with the workspace.  Setting this
     value at creation time allows the workspace being created to be linked to
     an existing workspace.
    :type customer_id: str
    :param portal_url: The URL of the Operational Insights portal for this
     workspace.  This value is set on the service side and read-only on the
     client side.
    :type portal_url: str
    :param sku: The SKU of the workspace.
    :type sku: ~azure.mgmt.loganalytics.models.Sku
    :param retention_in_days: The workspace data retention in days. -1 means
     Unlimited retention for the Unlimited Sku. 730 days is the maximum allowed
     for all other Skus.
    :type retention_in_days: int
    :param e_tag: The ETag of the workspace.
    :type e_tag: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'retention_in_days': {'maximum': 730, 'minimum': -1},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'source': {'key': 'properties.source', 'type': 'str'},
        'customer_id': {'key': 'properties.customerId', 'type': 'str'},
        'portal_url': {'key': 'properties.portalUrl', 'type': 'str'},
        'sku': {'key': 'properties.sku', 'type': 'Sku'},
        'retention_in_days': {'key': 'properties.retentionInDays', 'type': 'int'},
        'e_tag': {'key': 'eTag', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(Workspace, self).__init__(**kwargs)
        self.provisioning_state = kwargs.get('provisioning_state', None)
        self.source = kwargs.get('source', None)
        self.customer_id = kwargs.get('customer_id', None)
        self.portal_url = kwargs.get('portal_url', None)
        self.sku = kwargs.get('sku', None)
        self.retention_in_days = kwargs.get('retention_in_days', None)
        self.e_tag = kwargs.get('e_tag', None)
