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


class ApplicationInsightsComponentProactiveDetectionConfigurationRuleDefinitions(Model):
    """Static definitions of the ProactiveDetection configuration rule (same
    values for all components).

    :param name: The rule name
    :type name: str
    :param display_name: The rule name as it is displayed in UI
    :type display_name: str
    :param description: The rule description
    :type description: str
    :param help_url: URL which displays aditional info about the proactive
     detection rule
    :type help_url: str
    :param is_hidden: A flag indicating whether the rule is hidden (from the
     UI)
    :type is_hidden: bool
    :param is_enabled_by_default: A flag indicating whether the rule is
     enabled by default
    :type is_enabled_by_default: bool
    :param is_in_preview: A flag indicating whether the rule is in preview
    :type is_in_preview: bool
    :param supports_email_notifications: A flag indicating whether email
     notifications are supported for detections for this rule
    :type supports_email_notifications: bool
    """

    _attribute_map = {
        'name': {'key': 'Name', 'type': 'str'},
        'display_name': {'key': 'DisplayName', 'type': 'str'},
        'description': {'key': 'Description', 'type': 'str'},
        'help_url': {'key': 'HelpUrl', 'type': 'str'},
        'is_hidden': {'key': 'IsHidden', 'type': 'bool'},
        'is_enabled_by_default': {'key': 'IsEnabledByDefault', 'type': 'bool'},
        'is_in_preview': {'key': 'IsInPreview', 'type': 'bool'},
        'supports_email_notifications': {'key': 'SupportsEmailNotifications', 'type': 'bool'},
    }

    def __init__(self, *, name: str=None, display_name: str=None, description: str=None, help_url: str=None, is_hidden: bool=None, is_enabled_by_default: bool=None, is_in_preview: bool=None, supports_email_notifications: bool=None, **kwargs) -> None:
        super(ApplicationInsightsComponentProactiveDetectionConfigurationRuleDefinitions, self).__init__(**kwargs)
        self.name = name
        self.display_name = display_name
        self.description = description
        self.help_url = help_url
        self.is_hidden = is_hidden
        self.is_enabled_by_default = is_enabled_by_default
        self.is_in_preview = is_in_preview
        self.supports_email_notifications = supports_email_notifications
