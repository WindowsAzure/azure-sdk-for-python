# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class Provider(Model):
    """
    Resource provider information.

    :param id: Gets or sets the provider id.
    :type id: str
    :param namespace: Gets or sets the namespace of the provider.
    :type namespace: str
    :param registration_state: Gets or sets the registration state of the
     provider.
    :type registration_state: str
    :param resource_types: Gets or sets the collection of provider resource
     types.
    :type resource_types: list of :class:`ProviderResourceType
     <resourcemanagementclient.models.ProviderResourceType>`
    """ 

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'namespace': {'key': 'namespace', 'type': 'str'},
        'registration_state': {'key': 'registrationState', 'type': 'str'},
        'resource_types': {'key': 'resourceTypes', 'type': '[ProviderResourceType]'},
    }

    def __init__(self, id=None, namespace=None, registration_state=None, resource_types=None):
        self.id = id
        self.namespace = namespace
        self.registration_state = registration_state
        self.resource_types = resource_types
