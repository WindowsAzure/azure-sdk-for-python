# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from .resource import Resource


class TrackedResource(Resource):
    """
    ARM tracked resource

    :param id: Resource ID
    :type id: str
    :param name: Resource name
    :type name: str
    :param type: Resource type
    :type type: str
    :param location: Resource location
    :type location: str
    :param tags: Resource tags
    :type tags: dict
    """ 

    _validation = {
        'location': {'required': True},
        'tags': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, location, tags, id=None, name=None, type=None):
        super(TrackedResource, self).__init__(id=id, name=name, type=type)
        self.location = location
        self.tags = tags
