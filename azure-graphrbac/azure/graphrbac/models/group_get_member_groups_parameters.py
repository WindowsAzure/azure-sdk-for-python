# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class GroupGetMemberGroupsParameters(Model):
    """
    Request parameters for GetMemberGroups API call

    :param security_enabled_only: If true only membership in security enabled
     groups should be checked. Otherwise membership in all groups should be
     checked
    :type security_enabled_only: bool
    """ 

    _validation = {
        'security_enabled_only': {'required': True},
    }

    _attribute_map = {
        'security_enabled_only': {'key': 'securityEnabledOnly', 'type': 'bool'},
    }

    def __init__(self, security_enabled_only):
        self.security_enabled_only = security_enabled_only
