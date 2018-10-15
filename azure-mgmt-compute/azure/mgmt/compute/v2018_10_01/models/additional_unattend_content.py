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


class AdditionalUnattendContent(Model):
    """Specifies additional XML formatted information that can be included in the
    Unattend.xml file, which is used by Windows Setup. Contents are defined by
    setting name, component name, and the pass in which the content is applied.

    :param pass_name: The pass name. Currently, the only allowable value is
     OobeSystem. Possible values include: 'OobeSystem'
    :type pass_name: str or ~azure.mgmt.compute.v2018_10_01.models.PassNames
    :param component_name: The component name. Currently, the only allowable
     value is Microsoft-Windows-Shell-Setup. Possible values include:
     'Microsoft-Windows-Shell-Setup'
    :type component_name: str or
     ~azure.mgmt.compute.v2018_10_01.models.ComponentNames
    :param setting_name: Specifies the name of the setting to which the
     content applies. Possible values are: FirstLogonCommands and AutoLogon.
     Possible values include: 'AutoLogon', 'FirstLogonCommands'
    :type setting_name: str or
     ~azure.mgmt.compute.v2018_10_01.models.SettingNames
    :param content: Specifies the XML formatted content that is added to the
     unattend.xml file for the specified path and component. The XML must be
     less than 4KB and must include the root element for the setting or feature
     that is being inserted.
    :type content: str
    """

    _attribute_map = {
        'pass_name': {'key': 'passName', 'type': 'PassNames'},
        'component_name': {'key': 'componentName', 'type': 'ComponentNames'},
        'setting_name': {'key': 'settingName', 'type': 'SettingNames'},
        'content': {'key': 'content', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(AdditionalUnattendContent, self).__init__(**kwargs)
        self.pass_name = kwargs.get('pass_name', None)
        self.component_name = kwargs.get('component_name', None)
        self.setting_name = kwargs.get('setting_name', None)
        self.content = kwargs.get('content', None)
