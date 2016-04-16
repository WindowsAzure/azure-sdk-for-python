# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class OSDiskImage(Model):
    """
    Contains the os disk image information.

    :param operating_system: Gets or sets the operating system of the
     osDiskImage. Possible values include: 'Windows', 'Linux'
    :type operating_system: str
    """ 

    _validation = {
        'operating_system': {'required': True},
    }

    _attribute_map = {
        'operating_system': {'key': 'operatingSystem', 'type': 'OperatingSystemTypes'},
    }

    def __init__(self, operating_system):
        self.operating_system = operating_system
