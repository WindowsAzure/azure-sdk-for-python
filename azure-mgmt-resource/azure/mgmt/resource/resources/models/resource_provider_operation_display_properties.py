# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class ResourceProviderOperationDisplayProperties(Model):
    """
    Resource provider operation's display properties.

    :param publisher: Gets or sets operation description.
    :type publisher: str
    :param provider: Gets or sets operation provider.
    :type provider: str
    :param resource: Gets or sets operation resource.
    :type resource: str
    :param operation: Gets or sets operation.
    :type operation: str
    :param description: Gets or sets operation description.
    :type description: str
    """ 

    _attribute_map = {
        'publisher': {'key': 'publisher', 'type': 'str'},
        'provider': {'key': 'provider', 'type': 'str'},
        'resource': {'key': 'resource', 'type': 'str'},
        'operation': {'key': 'operation', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
    }

    def __init__(self, publisher=None, provider=None, resource=None, operation=None, description=None):
        self.publisher = publisher
        self.provider = provider
        self.resource = resource
        self.operation = operation
        self.description = description
