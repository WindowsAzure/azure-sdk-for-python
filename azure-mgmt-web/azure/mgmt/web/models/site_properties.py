# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class SiteProperties(Model):
    """SiteProperties

    :param metadata:
    :type metadata: list of :class:`NameValuePair
     <websitemanagementclient.models.NameValuePair>`
    :param properties:
    :type properties: list of :class:`NameValuePair
     <websitemanagementclient.models.NameValuePair>`
    :param app_settings:
    :type app_settings: list of :class:`NameValuePair
     <websitemanagementclient.models.NameValuePair>`
    """ 

    _attribute_map = {
        'metadata': {'key': 'metadata', 'type': '[NameValuePair]'},
        'properties': {'key': 'properties', 'type': '[NameValuePair]'},
        'app_settings': {'key': 'appSettings', 'type': '[NameValuePair]'},
    }

    def __init__(self, metadata=None, properties=None, app_settings=None):
        self.metadata = metadata
        self.properties = properties
        self.app_settings = app_settings
