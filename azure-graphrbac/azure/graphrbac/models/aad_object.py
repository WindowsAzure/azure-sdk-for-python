# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class AADObject(Model):
    """
    Active Directory object information

    :param object_id: Gets or sets object Id
    :type object_id: str
    :param object_type: Gets or sets object type
    :type object_type: str
    :param display_name: Gets or sets object display name
    :type display_name: str
    :param user_principal_name: Gets or sets principal name
    :type user_principal_name: str
    :param mail: Gets or sets mail
    :type mail: str
    :param mail_enabled: Gets or sets MailEnabled field
    :type mail_enabled: bool
    :param security_enabled: Gets or sets SecurityEnabled field
    :type security_enabled: bool
    :param sign_in_name: Gets or sets signIn name
    :type sign_in_name: str
    :param service_principal_names: Gets or sets the list of service
     principal names.
    :type service_principal_names: list of str
    :param user_type: Gets or sets the user type
    :type user_type: str
    """ 

    _attribute_map = {
        'object_id': {'key': 'objectId', 'type': 'str'},
        'object_type': {'key': 'objectType', 'type': 'str'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'user_principal_name': {'key': 'userPrincipalName', 'type': 'str'},
        'mail': {'key': 'mail', 'type': 'str'},
        'mail_enabled': {'key': 'mailEnabled', 'type': 'bool'},
        'security_enabled': {'key': 'securityEnabled', 'type': 'bool'},
        'sign_in_name': {'key': 'signInName', 'type': 'str'},
        'service_principal_names': {'key': 'servicePrincipalNames', 'type': '[str]'},
        'user_type': {'key': 'userType', 'type': 'str'},
    }

    def __init__(self, object_id=None, object_type=None, display_name=None, user_principal_name=None, mail=None, mail_enabled=None, security_enabled=None, sign_in_name=None, service_principal_names=None, user_type=None):
        self.object_id = object_id
        self.object_type = object_type
        self.display_name = display_name
        self.user_principal_name = user_principal_name
        self.mail = mail
        self.mail_enabled = mail_enabled
        self.security_enabled = security_enabled
        self.sign_in_name = sign_in_name
        self.service_principal_names = service_principal_names
        self.user_type = user_type
