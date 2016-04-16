# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class NodeFile(Model):
    """
    Information about a file or directory on a compute node.

    :param name: Gets or sets the file path.
    :type name: str
    :param url: Gets or sets the URL of the file.
    :type url: str
    :param is_directory: Gets or sets whether the object represents a
     directory.
    :type is_directory: bool
    :param properties: Gets or sets the file properties.
    :type properties: :class:`FileProperties
     <batchserviceclient.models.FileProperties>`
    """ 

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'url': {'key': 'url', 'type': 'str'},
        'is_directory': {'key': 'isDirectory', 'type': 'bool'},
        'properties': {'key': 'properties', 'type': 'FileProperties'},
    }

    def __init__(self, name=None, url=None, is_directory=None, properties=None):
        self.name = name
        self.url = url
        self.is_directory = is_directory
        self.properties = properties
