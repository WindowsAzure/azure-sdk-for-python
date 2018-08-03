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

from msrest.serialization import Model


class WebChatSite(Model):
    """A site for the Webchat channel.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar site_id: Site Id
    :vartype site_id: str
    :param site_name: Site name
    :type site_name: str
    :ivar key: Primary key. Value only returned through POST to the action
     Channel List API, otherwise empty.
    :vartype key: str
    :ivar key2: Secondary key. Value only returned through POST to the action
     Channel List API, otherwise empty.
    :vartype key2: str
    :param is_enabled: Whether this site is enabled for DirectLine channel
    :type is_enabled: bool
    :param enable_preview: Whether this site is enabled for preview versions
     of Webchat
    :type enable_preview: bool
    """

    _validation = {
        'site_id': {'readonly': True},
        'site_name': {'required': True},
        'key': {'readonly': True},
        'key2': {'readonly': True},
        'is_enabled': {'required': True},
        'enable_preview': {'required': True},
    }

    _attribute_map = {
        'site_id': {'key': 'siteId', 'type': 'str'},
        'site_name': {'key': 'siteName', 'type': 'str'},
        'key': {'key': 'key', 'type': 'str'},
        'key2': {'key': 'key2', 'type': 'str'},
        'is_enabled': {'key': 'isEnabled', 'type': 'bool'},
        'enable_preview': {'key': 'enablePreview', 'type': 'bool'},
    }

    def __init__(self, site_name, is_enabled, enable_preview):
        super(WebChatSite, self).__init__()
        self.site_id = None
        self.site_name = site_name
        self.key = None
        self.key2 = None
        self.is_enabled = is_enabled
        self.enable_preview = enable_preview
