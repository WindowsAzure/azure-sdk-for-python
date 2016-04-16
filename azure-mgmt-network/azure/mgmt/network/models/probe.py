# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from .sub_resource import SubResource


class Probe(SubResource):
    """
    Load balancer Probe

    :param id: Resource Id
    :type id: str
    :param load_balancing_rules: Gets Load balancer rules that use this probe
    :type load_balancing_rules: list of :class:`SubResource
     <networkmanagementclient.models.SubResource>`
    :param protocol: Gets or sets the protocol of the end point. Possible
     values are http pr Tcp. If Tcp is specified, a received ACK is required
     for the probe to be successful. If http is specified,a 200 OK response
     from the specifies URI is required for the probe to be successful.
     Possible values include: 'Http', 'Tcp'
    :type protocol: str
    :param port: Gets or sets Port for communicating the probe. Possible
     values range from 1 to 65535, inclusive.
    :type port: int
    :param interval_in_seconds: Gets or sets the interval, in seconds, for
     how frequently to probe the endpoint for health status. Typically, the
     interval is slightly less than half the allocated timeout period (in
     seconds) which allows two full probes before taking the instance out of
     rotation. The default value is 15, the minimum value is 5
    :type interval_in_seconds: int
    :param number_of_probes: Gets or sets the number of probes where if no
     response, will result in stopping further traffic from being delivered
     to the endpoint. This values allows endponints to be taken out of
     rotation faster or slower than the typical times used in Azure.
    :type number_of_probes: int
    :param request_path: Gets or sets the URI used for requesting health
     status from the VM. Path is required if a protocol is set to http.
     Otherwise, it is not allowed. There is no default value
    :type request_path: str
    :param provisioning_state: Gets or sets Provisioning state of the
     PublicIP resource Updating/Deleting/Failed
    :type provisioning_state: str
    :param name: Gets name of the resource that is unique within a resource
     group. This name can be used to access the resource
    :type name: str
    :param etag: A unique read-only string that changes whenever the resource
     is updated
    :type etag: str
    """ 

    _validation = {
        'protocol': {'required': True},
        'port': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'load_balancing_rules': {'key': 'properties.loadBalancingRules', 'type': '[SubResource]'},
        'protocol': {'key': 'properties.protocol', 'type': 'ProbeProtocol'},
        'port': {'key': 'properties.port', 'type': 'int'},
        'interval_in_seconds': {'key': 'properties.intervalInSeconds', 'type': 'int'},
        'number_of_probes': {'key': 'properties.numberOfProbes', 'type': 'int'},
        'request_path': {'key': 'properties.requestPath', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, protocol, port, id=None, load_balancing_rules=None, interval_in_seconds=None, number_of_probes=None, request_path=None, provisioning_state=None, name=None, etag=None):
        super(Probe, self).__init__(id=id)
        self.load_balancing_rules = load_balancing_rules
        self.protocol = protocol
        self.port = port
        self.interval_in_seconds = interval_in_seconds
        self.number_of_probes = number_of_probes
        self.request_path = request_path
        self.provisioning_state = provisioning_state
        self.name = name
        self.etag = etag
