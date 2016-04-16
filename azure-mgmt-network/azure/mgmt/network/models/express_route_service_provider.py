# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from .resource import Resource


class ExpressRouteServiceProvider(Resource):
    """
    ExpressRouteResourceProvider object

    :param id: Resource Id
    :type id: str
    :param name: Resource name
    :type name: str
    :param type: Resource type
    :type type: str
    :param location: Resource location
    :type location: str
    :param tags: Resource tags
    :type tags: dict
    :param peering_locations: Gets or list of peering locations
    :type peering_locations: list of str
    :param bandwidths_offered: Gets or bandwidths offered
    :type bandwidths_offered: list of
     :class:`ExpressRouteServiceProviderBandwidthsOffered
     <networkmanagementclient.models.ExpressRouteServiceProviderBandwidthsOffered>`
    :param provisioning_state: Gets or sets Provisioning state of the
     resource
    :type provisioning_state: str
    """ 

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'peering_locations': {'key': 'properties.peeringLocations', 'type': '[str]'},
        'bandwidths_offered': {'key': 'properties.bandwidthsOffered', 'type': '[ExpressRouteServiceProviderBandwidthsOffered]'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
    }

    def __init__(self, id=None, name=None, type=None, location=None, tags=None, peering_locations=None, bandwidths_offered=None, provisioning_state=None):
        super(ExpressRouteServiceProvider, self).__init__(id=id, name=name, type=type, location=location, tags=tags)
        self.peering_locations = peering_locations
        self.bandwidths_offered = bandwidths_offered
        self.provisioning_state = provisioning_state
