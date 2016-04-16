# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class SharedAccessAuthorizationRuleProperties(Model):
    """
    SharedAccessAuthorizationRule properties.

    :param primary_key: The primary key that was used.
    :type primary_key: str
    :param secondary_key: The secondary key that was used.
    :type secondary_key: str
    :param key_name: The name of the key that was used.
    :type key_name: str
    :param claim_type: The type of the claim.
    :type claim_type: str
    :param claim_value: The value of the claim.
    :type claim_value: str
    :param rights: The rights associated with the rule.
    :type rights: list of str
    :param created_time: The time at which the authorization rule was created.
    :type created_time: datetime
    :param modified_time: The most recent time the rule was updated.
    :type modified_time: datetime
    :param revision: The revision number for the rule.
    :type revision: int
    """ 

    _attribute_map = {
        'primary_key': {'key': 'primaryKey', 'type': 'str'},
        'secondary_key': {'key': 'secondaryKey', 'type': 'str'},
        'key_name': {'key': 'keyName', 'type': 'str'},
        'claim_type': {'key': 'claimType', 'type': 'str'},
        'claim_value': {'key': 'claimValue', 'type': 'str'},
        'rights': {'key': 'rights', 'type': '[AccessRights]'},
        'created_time': {'key': 'createdTime', 'type': 'iso-8601'},
        'modified_time': {'key': 'modifiedTime', 'type': 'iso-8601'},
        'revision': {'key': 'revision', 'type': 'int'},
    }

    def __init__(self, primary_key=None, secondary_key=None, key_name=None, claim_type=None, claim_value=None, rights=None, created_time=None, modified_time=None, revision=None):
        self.primary_key = primary_key
        self.secondary_key = secondary_key
        self.key_name = key_name
        self.claim_type = claim_type
        self.claim_value = claim_value
        self.rights = rights
        self.created_time = created_time
        self.modified_time = modified_time
        self.revision = revision
