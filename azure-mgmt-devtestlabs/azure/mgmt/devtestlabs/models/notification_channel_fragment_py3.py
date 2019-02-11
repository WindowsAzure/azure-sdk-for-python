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

from .update_resource_py3 import UpdateResource


class NotificationChannelFragment(UpdateResource):
    """A notification.

    :param tags: The tags of the resource.
    :type tags: dict[str, str]
    :param web_hook_url: The webhook URL to send notifications to.
    :type web_hook_url: str
    :param email_recipient: The email recipient to send notifications to (can
     be a list of semi-colon separated email addresses).
    :type email_recipient: str
    :param notification_locale: The locale to use when sending a notification
     (fallback for unsupported languages is EN).
    :type notification_locale: str
    :param description: Description of notification.
    :type description: str
    :param events: The list of event for which this notification is enabled.
    :type events: list[~azure.mgmt.devtestlabs.models.EventFragment]
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
        'web_hook_url': {'key': 'properties.webHookUrl', 'type': 'str'},
        'email_recipient': {'key': 'properties.emailRecipient', 'type': 'str'},
        'notification_locale': {'key': 'properties.notificationLocale', 'type': 'str'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'events': {'key': 'properties.events', 'type': '[EventFragment]'},
    }

    def __init__(self, *, tags=None, web_hook_url: str=None, email_recipient: str=None, notification_locale: str=None, description: str=None, events=None, **kwargs) -> None:
        super(NotificationChannelFragment, self).__init__(tags=tags, **kwargs)
        self.web_hook_url = web_hook_url
        self.email_recipient = email_recipient
        self.notification_locale = notification_locale
        self.description = description
        self.events = events
