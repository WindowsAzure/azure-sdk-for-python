# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class WnsCredentialProperties(Model):
    """
    Description of a NotificationHub WnsCredential.

    :param package_sid: Gets or sets the package ID for this credential.
    :type package_sid: str
    :param secret_key: Gets or sets the secret key.
    :type secret_key: str
    :param windows_live_endpoint: Gets or sets the Windows Live endpoint.
    :type windows_live_endpoint: str
    """ 

    _attribute_map = {
        'package_sid': {'key': 'packageSid', 'type': 'str'},
        'secret_key': {'key': 'secretKey', 'type': 'str'},
        'windows_live_endpoint': {'key': 'windowsLiveEndpoint', 'type': 'str'},
    }

    def __init__(self, package_sid=None, secret_key=None, windows_live_endpoint=None):
        self.package_sid = package_sid
        self.secret_key = secret_key
        self.windows_live_endpoint = windows_live_endpoint
