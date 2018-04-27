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


class DscMetaConfiguration(Model):
    """Definition of the DSC Meta Configuration.

    :param configuration_mode_frequency_mins: Gets or sets the
     ConfigurationModeFrequencyMins value of the meta configuration.
    :type configuration_mode_frequency_mins: int
    :param reboot_node_if_needed: Gets or sets the RebootNodeIfNeeded value of
     the meta configuration.
    :type reboot_node_if_needed: bool
    :param configuration_mode: Gets or sets the ConfigurationMode value of the
     meta configuration.
    :type configuration_mode: str
    :param action_after_reboot: Gets or sets the ActionAfterReboot value of
     the meta configuration.
    :type action_after_reboot: str
    :param certificate_id: Gets or sets the CertificateId value of the meta
     configuration.
    :type certificate_id: str
    :param refresh_frequency_mins: Gets or sets the RefreshFrequencyMins value
     of the meta configuration.
    :type refresh_frequency_mins: int
    :param allow_module_overwrite: Gets or sets the AllowModuleOverwrite value
     of the meta configuration.
    :type allow_module_overwrite: bool
    """

    _attribute_map = {
        'configuration_mode_frequency_mins': {'key': 'configurationModeFrequencyMins', 'type': 'int'},
        'reboot_node_if_needed': {'key': 'rebootNodeIfNeeded', 'type': 'bool'},
        'configuration_mode': {'key': 'configurationMode', 'type': 'str'},
        'action_after_reboot': {'key': 'actionAfterReboot', 'type': 'str'},
        'certificate_id': {'key': 'certificateId', 'type': 'str'},
        'refresh_frequency_mins': {'key': 'refreshFrequencyMins', 'type': 'int'},
        'allow_module_overwrite': {'key': 'allowModuleOverwrite', 'type': 'bool'},
    }

    def __init__(self, *, configuration_mode_frequency_mins: int=None, reboot_node_if_needed: bool=None, configuration_mode: str=None, action_after_reboot: str=None, certificate_id: str=None, refresh_frequency_mins: int=None, allow_module_overwrite: bool=None, **kwargs) -> None:
        super(DscMetaConfiguration, self).__init__(**kwargs)
        self.configuration_mode_frequency_mins = configuration_mode_frequency_mins
        self.reboot_node_if_needed = reboot_node_if_needed
        self.configuration_mode = configuration_mode
        self.action_after_reboot = action_after_reboot
        self.certificate_id = certificate_id
        self.refresh_frequency_mins = refresh_frequency_mins
        self.allow_module_overwrite = allow_module_overwrite
