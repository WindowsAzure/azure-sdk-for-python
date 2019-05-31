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


class SystemService(Model):
    """Information about a system service deployed in the cluster.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param system_service_type: Required. The system service type. Possible
     values include: 'None', 'ScoringFrontEnd', 'BatchFrontEnd'
    :type system_service_type: str or
     ~azure.mgmt.machinelearningcompute.models.SystemServiceType
    :ivar public_ip_address: The public IP address of the system service
    :vartype public_ip_address: str
    :ivar version: The state of the system service
    :vartype version: str
    """

    _validation = {
        'system_service_type': {'required': True},
        'public_ip_address': {'readonly': True},
        'version': {'readonly': True},
    }

    _attribute_map = {
        'system_service_type': {'key': 'systemServiceType', 'type': 'str'},
        'public_ip_address': {'key': 'publicIpAddress', 'type': 'str'},
        'version': {'key': 'version', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(SystemService, self).__init__(**kwargs)
        self.system_service_type = kwargs.get('system_service_type', None)
        self.public_ip_address = None
        self.version = None
