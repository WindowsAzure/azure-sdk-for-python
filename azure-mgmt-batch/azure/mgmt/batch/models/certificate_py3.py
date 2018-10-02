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

from .proxy_resource_py3 import ProxyResource


class Certificate(ProxyResource):
    """Contains information about a certificate.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: The ID of the resource.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource.
    :vartype type: str
    :ivar etag: The ETag of the resource, used for concurrency statements.
    :vartype etag: str
    :param thumbprint_algorithm: The algorithm of the certificate thumbprint.
     This must match the first portion of the certificate name. Currently
     required to be 'SHA1'.
    :type thumbprint_algorithm: str
    :param thumbprint: The thumbprint of the certificate. This must match the
     thumbprint from the name.
    :type thumbprint: str
    :param format: The format of the certificate - either Pfx or Cer. If
     omitted, the default is Pfx. Possible values include: 'Pfx', 'Cer'
    :type format: str or ~azure.mgmt.batch.models.CertificateFormat
    :ivar provisioning_state: The provisioned state of the resource. Values
     are:
     Succeeded - The certificate is available for use in pools.
     Deleting - The user has requested that the certificate be deleted, but the
     delete operation has not yet completed. You may not reference the
     certificate when creating or updating pools.
     Failed - The user requested that the certificate be deleted, but there are
     pools that still have references to the certificate, or it is still
     installed on one or more compute nodes. (The latter can occur if the
     certificate has been removed from the pool, but the node has not yet
     restarted. Nodes refresh their certificates only when they restart.) You
     may use the cancel certificate delete operation to cancel the delete, or
     the delete certificate operation to retry the delete. Possible values
     include: 'Succeeded', 'Deleting', 'Failed'
    :vartype provisioning_state: str or
     ~azure.mgmt.batch.models.CertificateProvisioningState
    :ivar provisioning_state_transition_time: The time at which the
     certificate entered its current state.
    :vartype provisioning_state_transition_time: datetime
    :ivar previous_provisioning_state: The previous provisioned state of the
     resource. Possible values include: 'Succeeded', 'Deleting', 'Failed'
    :vartype previous_provisioning_state: str or
     ~azure.mgmt.batch.models.CertificateProvisioningState
    :ivar previous_provisioning_state_transition_time: The time at which the
     certificate entered its previous state.
    :vartype previous_provisioning_state_transition_time: datetime
    :ivar public_data: The public key of the certificate.
    :vartype public_data: str
    :ivar delete_certificate_error: The error which occurred while deleting
     the certificate. This is only returned when the certificate
     provisioningState is 'Failed'.
    :vartype delete_certificate_error:
     ~azure.mgmt.batch.models.DeleteCertificateError
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'etag': {'readonly': True},
        'provisioning_state': {'readonly': True},
        'provisioning_state_transition_time': {'readonly': True},
        'previous_provisioning_state': {'readonly': True},
        'previous_provisioning_state_transition_time': {'readonly': True},
        'public_data': {'readonly': True},
        'delete_certificate_error': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'thumbprint_algorithm': {'key': 'properties.thumbprintAlgorithm', 'type': 'str'},
        'thumbprint': {'key': 'properties.thumbprint', 'type': 'str'},
        'format': {'key': 'properties.format', 'type': 'CertificateFormat'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'CertificateProvisioningState'},
        'provisioning_state_transition_time': {'key': 'properties.provisioningStateTransitionTime', 'type': 'iso-8601'},
        'previous_provisioning_state': {'key': 'properties.previousProvisioningState', 'type': 'CertificateProvisioningState'},
        'previous_provisioning_state_transition_time': {'key': 'properties.previousProvisioningStateTransitionTime', 'type': 'iso-8601'},
        'public_data': {'key': 'properties.publicData', 'type': 'str'},
        'delete_certificate_error': {'key': 'properties.deleteCertificateError', 'type': 'DeleteCertificateError'},
    }

    def __init__(self, *, thumbprint_algorithm: str=None, thumbprint: str=None, format=None, **kwargs) -> None:
        super(Certificate, self).__init__(**kwargs)
        self.thumbprint_algorithm = thumbprint_algorithm
        self.thumbprint = thumbprint
        self.format = format
        self.provisioning_state = None
        self.provisioning_state_transition_time = None
        self.previous_provisioning_state = None
        self.previous_provisioning_state_transition_time = None
        self.public_data = None
        self.delete_certificate_error = None
