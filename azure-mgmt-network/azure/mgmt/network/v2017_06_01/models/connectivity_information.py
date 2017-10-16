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


class ConnectivityInformation(Model):
    """Information on the connectivity status.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar hops: List of hops between the source and the destination.
    :vartype hops:
     list[~azure.mgmt.network.v2017_06_01.models.ConnectivityHop]
    :ivar connection_status: The connection status. Possible values include:
     'Unknown', 'Connected', 'Disconnected', 'Degraded'
    :vartype connection_status: str or
     ~azure.mgmt.network.v2017_06_01.models.ConnectionStatus
    :ivar avg_latency_in_ms: Average latency in milliseconds.
    :vartype avg_latency_in_ms: int
    :ivar min_latency_in_ms: Minimum latency in milliseconds.
    :vartype min_latency_in_ms: int
    :ivar max_latency_in_ms: Maximum latency in milliseconds.
    :vartype max_latency_in_ms: int
    :ivar probes_sent: Total number of probes sent.
    :vartype probes_sent: int
    :ivar probes_failed: Number of failed probes.
    :vartype probes_failed: int
    """

    _validation = {
        'hops': {'readonly': True},
        'connection_status': {'readonly': True},
        'avg_latency_in_ms': {'readonly': True},
        'min_latency_in_ms': {'readonly': True},
        'max_latency_in_ms': {'readonly': True},
        'probes_sent': {'readonly': True},
        'probes_failed': {'readonly': True},
    }

    _attribute_map = {
        'hops': {'key': 'hops', 'type': '[ConnectivityHop]'},
        'connection_status': {'key': 'connectionStatus', 'type': 'str'},
        'avg_latency_in_ms': {'key': 'avgLatencyInMs', 'type': 'int'},
        'min_latency_in_ms': {'key': 'minLatencyInMs', 'type': 'int'},
        'max_latency_in_ms': {'key': 'maxLatencyInMs', 'type': 'int'},
        'probes_sent': {'key': 'probesSent', 'type': 'int'},
        'probes_failed': {'key': 'probesFailed', 'type': 'int'},
    }

    def __init__(self):
        self.hops = None
        self.connection_status = None
        self.avg_latency_in_ms = None
        self.min_latency_in_ms = None
        self.max_latency_in_ms = None
        self.probes_sent = None
        self.probes_failed = None
