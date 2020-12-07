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

from msrest.paging import Paged


class ServerPaged(Paged):
    """
    A paging container for iterating over a list of :class:`Server <azure.mgmt.rdbms.postgresql_flexibleservers.models.Server>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Server]'}
    }

    def __init__(self, *args, **kwargs):

        super(ServerPaged, self).__init__(*args, **kwargs)
class FirewallRulePaged(Paged):
    """
    A paging container for iterating over a list of :class:`FirewallRule <azure.mgmt.rdbms.postgresql_flexibleservers.models.FirewallRule>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[FirewallRule]'}
    }

    def __init__(self, *args, **kwargs):

        super(FirewallRulePaged, self).__init__(*args, **kwargs)
class ConfigurationPaged(Paged):
    """
    A paging container for iterating over a list of :class:`Configuration <azure.mgmt.rdbms.postgresql_flexibleservers.models.Configuration>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Configuration]'}
    }

    def __init__(self, *args, **kwargs):

        super(ConfigurationPaged, self).__init__(*args, **kwargs)
class CapabilityPropertiesPaged(Paged):
    """
    A paging container for iterating over a list of :class:`CapabilityProperties <azure.mgmt.rdbms.postgresql_flexibleservers.models.CapabilityProperties>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[CapabilityProperties]'}
    }

    def __init__(self, *args, **kwargs):

        super(CapabilityPropertiesPaged, self).__init__(*args, **kwargs)
class DatabasePaged(Paged):
    """
    A paging container for iterating over a list of :class:`Database <azure.mgmt.rdbms.postgresql_flexibleservers.models.Database>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Database]'}
    }

    def __init__(self, *args, **kwargs):

        super(DatabasePaged, self).__init__(*args, **kwargs)
