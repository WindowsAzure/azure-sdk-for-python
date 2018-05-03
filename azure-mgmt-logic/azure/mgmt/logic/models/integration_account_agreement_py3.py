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


class IntegrationAccountAgreement(Resource):
    """The integration account agreement.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: The resource id.
    :vartype id: str
    :ivar name: Gets the resource name.
    :vartype name: str
    :ivar type: Gets the resource type.
    :vartype type: str
    :param location: The resource location.
    :type location: str
    :param tags: The resource tags.
    :type tags: dict[str, str]
    :ivar created_time: The created time.
    :vartype created_time: datetime
    :ivar changed_time: The changed time.
    :vartype changed_time: datetime
    :param metadata: The metadata.
    :type metadata: object
    :param agreement_type: Required. The agreement type. Possible values
     include: 'NotSpecified', 'AS2', 'X12', 'Edifact'
    :type agreement_type: str or ~azure.mgmt.logic.models.AgreementType
    :param host_partner: Required. The integration account partner that is set
     as host partner for this agreement.
    :type host_partner: str
    :param guest_partner: Required. The integration account partner that is
     set as guest partner for this agreement.
    :type guest_partner: str
    :param host_identity: Required. The business identity of the host partner.
    :type host_identity: ~azure.mgmt.logic.models.BusinessIdentity
    :param guest_identity: Required. The business identity of the guest
     partner.
    :type guest_identity: ~azure.mgmt.logic.models.BusinessIdentity
    :param content: Required. The agreement content.
    :type content: ~azure.mgmt.logic.models.AgreementContent
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'created_time': {'readonly': True},
        'changed_time': {'readonly': True},
        'agreement_type': {'required': True},
        'host_partner': {'required': True},
        'guest_partner': {'required': True},
        'host_identity': {'required': True},
        'guest_identity': {'required': True},
        'content': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'created_time': {'key': 'properties.createdTime', 'type': 'iso-8601'},
        'changed_time': {'key': 'properties.changedTime', 'type': 'iso-8601'},
        'metadata': {'key': 'properties.metadata', 'type': 'object'},
        'agreement_type': {'key': 'properties.agreementType', 'type': 'AgreementType'},
        'host_partner': {'key': 'properties.hostPartner', 'type': 'str'},
        'guest_partner': {'key': 'properties.guestPartner', 'type': 'str'},
        'host_identity': {'key': 'properties.hostIdentity', 'type': 'BusinessIdentity'},
        'guest_identity': {'key': 'properties.guestIdentity', 'type': 'BusinessIdentity'},
        'content': {'key': 'properties.content', 'type': 'AgreementContent'},
    }

    def __init__(self, *, agreement_type, host_partner: str, guest_partner: str, host_identity, guest_identity, content, location: str=None, tags=None, metadata=None, **kwargs) -> None:
        super(IntegrationAccountAgreement, self).__init__(location=location, tags=tags, **kwargs)
        self.created_time = None
        self.changed_time = None
        self.metadata = metadata
        self.agreement_type = agreement_type
        self.host_partner = host_partner
        self.guest_partner = guest_partner
        self.host_identity = host_identity
        self.guest_identity = guest_identity
        self.content = content
