# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from enum import Enum, EnumMeta
from six import with_metaclass

class _CaseInsensitiveEnumMeta(EnumMeta):
    def __getitem__(self, name):
        return super().__getitem__(name.upper())

    def __getattr__(cls, name):
        """Return the enum member matching `name`
        We use __getattr__ instead of descriptors or inserting into the enum
        class' __dict__ in order to support `name` and `value` being both
        properties for enum members (which live in the class' __dict__) and
        enum members themselves.
        """
        try:
            return cls._member_map_[name.upper()]
        except KeyError:
            raise AttributeError(name)


class CloudServiceUpgradeMode(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Update mode for the cloud service. Role instances are allocated to update domains when the
    service is deployed. Updates can be initiated manually in each update domain or initiated
    automatically in all update domains.
    Possible Values are :code:`<br />`:code:`<br />`\ **Auto**\ :code:`<br />`:code:`<br />`\
    **Manual** :code:`<br />`:code:`<br />`\ **Simultaneous**\ :code:`<br />`:code:`<br />`
    If not specified, the default value is Auto. If set to Manual, PUT UpdateDomain must be called
    to apply the update. If set to Auto, the update is automatically applied to each update domain
    in sequence.
    """

    AUTO = "Auto"
    MANUAL = "Manual"
    SIMULTANEOUS = "Simultaneous"

class StatusLevelTypes(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The level code.
    """

    INFO = "Info"
    WARNING = "Warning"
    ERROR = "Error"
