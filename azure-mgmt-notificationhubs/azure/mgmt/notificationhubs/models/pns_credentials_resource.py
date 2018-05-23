# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from .resource import Resource


class PnsCredentialsResource(Resource):
    """Description of a NotificationHub PNS Credentials.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id
    :vartype id: str
    :ivar name: Resource name
    :vartype name: str
    :ivar type: Resource type
    :vartype type: str
    :param location: Resource location
    :type location: str
    :param tags: Resource tags
    :type tags: dict[str, str]
    :param sku: The sku of the created namespace
    :type sku: ~azure.mgmt.notificationhubs.models.Sku
    :param apns_credential: The ApnsCredential of the created NotificationHub
    :type apns_credential: ~azure.mgmt.notificationhubs.models.ApnsCredential
    :param wns_credential: The WnsCredential of the created NotificationHub
    :type wns_credential: ~azure.mgmt.notificationhubs.models.WnsCredential
    :param gcm_credential: The GcmCredential of the created NotificationHub
    :type gcm_credential: ~azure.mgmt.notificationhubs.models.GcmCredential
    :param mpns_credential: The MpnsCredential of the created NotificationHub
    :type mpns_credential: ~azure.mgmt.notificationhubs.models.MpnsCredential
    :param adm_credential: The AdmCredential of the created NotificationHub
    :type adm_credential: ~azure.mgmt.notificationhubs.models.AdmCredential
    :param baidu_credential: The BaiduCredential of the created
     NotificationHub
    :type baidu_credential:
     ~azure.mgmt.notificationhubs.models.BaiduCredential
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'sku': {'key': 'sku', 'type': 'Sku'},
        'apns_credential': {'key': 'properties.apnsCredential', 'type': 'ApnsCredential'},
        'wns_credential': {'key': 'properties.wnsCredential', 'type': 'WnsCredential'},
        'gcm_credential': {'key': 'properties.gcmCredential', 'type': 'GcmCredential'},
        'mpns_credential': {'key': 'properties.mpnsCredential', 'type': 'MpnsCredential'},
        'adm_credential': {'key': 'properties.admCredential', 'type': 'AdmCredential'},
        'baidu_credential': {'key': 'properties.baiduCredential', 'type': 'BaiduCredential'},
    }

    def __init__(self, **kwargs):
        super(PnsCredentialsResource, self).__init__(**kwargs)
        self.apns_credential = kwargs.get('apns_credential', None)
        self.wns_credential = kwargs.get('wns_credential', None)
        self.gcm_credential = kwargs.get('gcm_credential', None)
        self.mpns_credential = kwargs.get('mpns_credential', None)
        self.adm_credential = kwargs.get('adm_credential', None)
        self.baidu_credential = kwargs.get('baidu_credential', None)
