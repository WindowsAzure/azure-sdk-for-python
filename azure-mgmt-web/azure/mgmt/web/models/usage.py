# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from .resource import Resource


class Usage(Resource):
    """
    Class that represents usage of the quota resource.

    :param id: Resource Id
    :type id: str
    :param name: Resource Name
    :type name: str
    :param kind: Kind of resource
    :type kind: str
    :param location: Resource Location
    :type location: str
    :param type: Resource type
    :type type: str
    :param tags: Resource tags
    :type tags: dict
    :param display_name: Friendly name shown in the UI
    :type display_name: str
    :param usage_name: Name of the quota
    :type usage_name: str
    :param resource_name: Name of the quota resource
    :type resource_name: str
    :param unit: Units of measurement for the quota resource
    :type unit: str
    :param current_value: The current value of the resource counter
    :type current_value: long
    :param limit: The resource limit
    :type limit: long
    :param next_reset_time: Next reset time for the resource counter
    :type next_reset_time: datetime
    :param compute_mode: ComputeMode used for this usage. Possible values
     include: 'Shared', 'Dedicated', 'Dynamic'
    :type compute_mode: str
    :param site_mode: SiteMode used for this usage
    :type site_mode: str
    """ 

    _validation = {
        'location': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'display_name': {'key': 'properties.displayName', 'type': 'str'},
        'usage_name': {'key': 'properties.name', 'type': 'str'},
        'resource_name': {'key': 'properties.resourceName', 'type': 'str'},
        'unit': {'key': 'properties.unit', 'type': 'str'},
        'current_value': {'key': 'properties.currentValue', 'type': 'long'},
        'limit': {'key': 'properties.limit', 'type': 'long'},
        'next_reset_time': {'key': 'properties.nextResetTime', 'type': 'iso-8601'},
        'compute_mode': {'key': 'properties.computeMode', 'type': 'ComputeModeOptions'},
        'site_mode': {'key': 'properties.siteMode', 'type': 'str'},
    }

    def __init__(self, location, id=None, name=None, kind=None, type=None, tags=None, display_name=None, usage_name=None, resource_name=None, unit=None, current_value=None, limit=None, next_reset_time=None, compute_mode=None, site_mode=None):
        super(Usage, self).__init__(id=id, name=name, kind=kind, location=location, type=type, tags=tags)
        self.display_name = display_name
        self.usage_name = usage_name
        self.resource_name = resource_name
        self.unit = unit
        self.current_value = current_value
        self.limit = limit
        self.next_reset_time = next_reset_time
        self.compute_mode = compute_mode
        self.site_mode = site_mode
