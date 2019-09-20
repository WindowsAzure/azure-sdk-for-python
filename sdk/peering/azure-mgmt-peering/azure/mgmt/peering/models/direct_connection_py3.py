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


class DirectConnection(Model):
    """The properties that define a direct connection.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param bandwidth_in_mbps: The bandwidth of the connection.
    :type bandwidth_in_mbps: int
    :param provisioned_bandwidth_in_mbps: The bandwidth that is actually
     provisioned.
    :type provisioned_bandwidth_in_mbps: int
    :param session_address_provider: The field indicating if Microsoft
     provides session ip addresses. Possible values include: 'Microsoft',
     'Peer'
    :type session_address_provider: str or
     ~azure.mgmt.peering.models.SessionAddressProvider
    :param use_for_peering_service: The flag that indicates whether or not the
     connection is used for peering service.
    :type use_for_peering_service: bool
    :param peering_db_facility_id: The PeeringDB.com ID of the facility at
     which the connection has to be set up.
    :type peering_db_facility_id: int
    :ivar connection_state: The state of the connection. Possible values
     include: 'None', 'PendingApproval', 'Approved', 'ProvisioningStarted',
     'ProvisioningFailed', 'ProvisioningCompleted', 'Validating', 'Active'
    :vartype connection_state: str or
     ~azure.mgmt.peering.models.ConnectionState
    :param bgp_session: The BGP session associated with the connection.
    :type bgp_session: ~azure.mgmt.peering.models.BgpSession
    :param connection_identifier: The unique identifier (GUID) for the
     connection.
    :type connection_identifier: str
    """

    _validation = {
        'connection_state': {'readonly': True},
    }

    _attribute_map = {
        'bandwidth_in_mbps': {'key': 'bandwidthInMbps', 'type': 'int'},
        'provisioned_bandwidth_in_mbps': {'key': 'provisionedBandwidthInMbps', 'type': 'int'},
        'session_address_provider': {'key': 'sessionAddressProvider', 'type': 'str'},
        'use_for_peering_service': {'key': 'useForPeeringService', 'type': 'bool'},
        'peering_db_facility_id': {'key': 'peeringDBFacilityId', 'type': 'int'},
        'connection_state': {'key': 'connectionState', 'type': 'str'},
        'bgp_session': {'key': 'bgpSession', 'type': 'BgpSession'},
        'connection_identifier': {'key': 'connectionIdentifier', 'type': 'str'},
    }

    def __init__(self, *, bandwidth_in_mbps: int=None, provisioned_bandwidth_in_mbps: int=None, session_address_provider=None, use_for_peering_service: bool=None, peering_db_facility_id: int=None, bgp_session=None, connection_identifier: str=None, **kwargs) -> None:
        super(DirectConnection, self).__init__(**kwargs)
        self.bandwidth_in_mbps = bandwidth_in_mbps
        self.provisioned_bandwidth_in_mbps = provisioned_bandwidth_in_mbps
        self.session_address_provider = session_address_provider
        self.use_for_peering_service = use_for_peering_service
        self.peering_db_facility_id = peering_db_facility_id
        self.connection_state = None
        self.bgp_session = bgp_session
        self.connection_identifier = connection_identifier
