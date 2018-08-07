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


class ContentKeyPolicyPlayReadyLicense(Model):
    """The PlayReady license.

    All required parameters must be populated in order to send to Azure.

    :param allow_test_devices: Required. A flag indicating whether test
     devices can use the license.
    :type allow_test_devices: bool
    :param begin_date: The begin date of license
    :type begin_date: datetime
    :param expiration_date: The expiration date of license.
    :type expiration_date: datetime
    :param relative_begin_date: The relative begin date of license.
    :type relative_begin_date: timedelta
    :param relative_expiration_date: The relative expiration date of license.
    :type relative_expiration_date: timedelta
    :param grace_period: The grace period of license.
    :type grace_period: timedelta
    :param play_right: The license PlayRight
    :type play_right:
     ~azure.mgmt.media.models.ContentKeyPolicyPlayReadyPlayRight
    :param license_type: Required. The license type. Possible values include:
     'Unknown', 'NonPersistent', 'Persistent'
    :type license_type: str or
     ~azure.mgmt.media.models.ContentKeyPolicyPlayReadyLicenseType
    :param content_key_location: Required. The content key location.
    :type content_key_location:
     ~azure.mgmt.media.models.ContentKeyPolicyPlayReadyContentKeyLocation
    :param content_type: Required. The PlayReady content type. Possible values
     include: 'Unknown', 'Unspecified', 'UltraVioletDownload',
     'UltraVioletStreaming'
    :type content_type: str or
     ~azure.mgmt.media.models.ContentKeyPolicyPlayReadyContentType
    """

    _validation = {
        'allow_test_devices': {'required': True},
        'license_type': {'required': True},
        'content_key_location': {'required': True},
        'content_type': {'required': True},
    }

    _attribute_map = {
        'allow_test_devices': {'key': 'allowTestDevices', 'type': 'bool'},
        'begin_date': {'key': 'beginDate', 'type': 'iso-8601'},
        'expiration_date': {'key': 'expirationDate', 'type': 'iso-8601'},
        'relative_begin_date': {'key': 'relativeBeginDate', 'type': 'duration'},
        'relative_expiration_date': {'key': 'relativeExpirationDate', 'type': 'duration'},
        'grace_period': {'key': 'gracePeriod', 'type': 'duration'},
        'play_right': {'key': 'playRight', 'type': 'ContentKeyPolicyPlayReadyPlayRight'},
        'license_type': {'key': 'licenseType', 'type': 'ContentKeyPolicyPlayReadyLicenseType'},
        'content_key_location': {'key': 'contentKeyLocation', 'type': 'ContentKeyPolicyPlayReadyContentKeyLocation'},
        'content_type': {'key': 'contentType', 'type': 'ContentKeyPolicyPlayReadyContentType'},
    }

    def __init__(self, *, allow_test_devices: bool, license_type, content_key_location, content_type, begin_date=None, expiration_date=None, relative_begin_date=None, relative_expiration_date=None, grace_period=None, play_right=None, **kwargs) -> None:
        super(ContentKeyPolicyPlayReadyLicense, self).__init__(**kwargs)
        self.allow_test_devices = allow_test_devices
        self.begin_date = begin_date
        self.expiration_date = expiration_date
        self.relative_begin_date = relative_begin_date
        self.relative_expiration_date = relative_expiration_date
        self.grace_period = grace_period
        self.play_right = play_right
        self.license_type = license_type
        self.content_key_location = content_key_location
        self.content_type = content_type
