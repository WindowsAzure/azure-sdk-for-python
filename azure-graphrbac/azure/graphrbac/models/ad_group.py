# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class ADGroup(Model):
    """
    Active Directory group information

    :param object_id: Gets or sets object Id
    :type object_id: str
    :param object_type: Gets or sets object type
    :type object_type: str
    :param display_name: Gets or sets group display name
    :type display_name: str
    :param security_enabled: Gets or sets security enabled field
    :type security_enabled: bool
    :param mail: Gets or sets mail field
    :type mail: str
    """ 

    _attribute_map = {
        'object_id': {'key': 'objectId', 'type': 'str'},
        'object_type': {'key': 'objectType', 'type': 'str'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'security_enabled': {'key': 'securityEnabled', 'type': 'bool'},
        'mail': {'key': 'mail', 'type': 'str'},
    }

    def __init__(self, object_id=None, object_type=None, display_name=None, security_enabled=None, mail=None):
        self.object_id = object_id
        self.object_type = object_type
        self.display_name = display_name
        self.security_enabled = security_enabled
        self.mail = mail
