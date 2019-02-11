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

from .settings import Settings


class UebaSettings(Settings):
    """Represents settings for UEBA enablement.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Azure resource Id
    :vartype id: str
    :ivar type: Azure resource type
    :vartype type: str
    :ivar name: Azure resource name
    :vartype name: str
    :param kind: Required. Constant filled by server.
    :type kind: str
    :param is_enabled: Determines whether UEBA is enabled for this workspace.
    :type is_enabled: bool
    :ivar status_in_mcas: Determines whether UEBA is enabled from MCAS.
     Possible values include: 'Enabled', 'Disabled'
    :vartype status_in_mcas: str or
     ~azure.mgmt.securityinsight.models.StatusInMcas
    :ivar atp_license_status: Determines whether the tenant .
    :vartype atp_license_status: bool
    """

    _validation = {
        'id': {'readonly': True},
        'type': {'readonly': True},
        'name': {'readonly': True},
        'kind': {'required': True},
        'status_in_mcas': {'readonly': True},
        'atp_license_status': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'is_enabled': {'key': 'properties.isEnabled', 'type': 'bool'},
        'status_in_mcas': {'key': 'properties.statusInMcas', 'type': 'str'},
        'atp_license_status': {'key': 'properties.atpLicenseStatus', 'type': 'bool'},
    }

    def __init__(self, **kwargs):
        super(UebaSettings, self).__init__(**kwargs)
        self.is_enabled = kwargs.get('is_enabled', None)
        self.status_in_mcas = None
        self.atp_license_status = None
        self.kind = 'UebaSettings'
