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


class LabAnnouncementProperties(Model):
    """Properties of a lab's announcement banner.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param title: The plain text title for the lab announcement
    :type title: str
    :param markdown: The markdown text (if any) that this lab displays in the
     UI. If left empty/null, nothing will be shown.
    :type markdown: str
    :param enabled: Is the lab announcement active/enabled at this time?.
     Possible values include: 'Enabled', 'Disabled'
    :type enabled: str or ~azure.mgmt.devtestlabs.models.EnableStatus
    :param expiration_date: The time at which the announcement expires (null
     for never)
    :type expiration_date: datetime
    :param expired: Has this announcement expired?
    :type expired: bool
    :ivar provisioning_state: The provisioning status of the resource.
    :vartype provisioning_state: str
    :ivar unique_identifier: The unique immutable identifier of a resource
     (Guid).
    :vartype unique_identifier: str
    """

    _validation = {
        'provisioning_state': {'readonly': True},
        'unique_identifier': {'readonly': True},
    }

    _attribute_map = {
        'title': {'key': 'title', 'type': 'str'},
        'markdown': {'key': 'markdown', 'type': 'str'},
        'enabled': {'key': 'enabled', 'type': 'str'},
        'expiration_date': {'key': 'expirationDate', 'type': 'iso-8601'},
        'expired': {'key': 'expired', 'type': 'bool'},
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
        'unique_identifier': {'key': 'uniqueIdentifier', 'type': 'str'},
    }

    def __init__(self, *, title: str=None, markdown: str=None, enabled=None, expiration_date=None, expired: bool=None, **kwargs) -> None:
        super(LabAnnouncementProperties, self).__init__(**kwargs)
        self.title = title
        self.markdown = markdown
        self.enabled = enabled
        self.expiration_date = expiration_date
        self.expired = expired
        self.provisioning_state = None
        self.unique_identifier = None
