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


class UpgradePolicy(Model):
    """Describes an upgrade policy - automatic, manual, or rolling.

    :param mode: Specifies the mode of an upgrade to virtual machines in the
     scale set.<br /><br /> Possible values are:<br /><br /> **Manual** - You
     control the application of updates to virtual machines in the scale set.
     You do this by using the manualUpgrade action.<br /><br /> **Automatic** -
     All virtual machines in the scale set are  automatically updated at the
     same time. Possible values include: 'Automatic', 'Manual', 'Rolling'
    :type mode: str or ~azure.mgmt.compute.v2017_12_01.models.UpgradeMode
    :param rolling_upgrade_policy: The configuration parameters used while
     performing a rolling upgrade.
    :type rolling_upgrade_policy:
     ~azure.mgmt.compute.v2017_12_01.models.RollingUpgradePolicy
    :param automatic_os_upgrade: Whether OS upgrades should automatically be
     applied to scale set instances in a rolling fashion when a newer version
     of the image becomes available.
    :type automatic_os_upgrade: bool
    :param auto_os_upgrade_policy: Configuration parameters used for
     performing automatic OS Upgrade.
    :type auto_os_upgrade_policy:
     ~azure.mgmt.compute.v2017_12_01.models.AutoOSUpgradePolicy
    """

    _attribute_map = {
        'mode': {'key': 'mode', 'type': 'UpgradeMode'},
        'rolling_upgrade_policy': {'key': 'rollingUpgradePolicy', 'type': 'RollingUpgradePolicy'},
        'automatic_os_upgrade': {'key': 'automaticOSUpgrade', 'type': 'bool'},
        'auto_os_upgrade_policy': {'key': 'autoOSUpgradePolicy', 'type': 'AutoOSUpgradePolicy'},
    }

    def __init__(self, **kwargs):
        super(UpgradePolicy, self).__init__(**kwargs)
        self.mode = kwargs.get('mode', None)
        self.rolling_upgrade_policy = kwargs.get('rolling_upgrade_policy', None)
        self.automatic_os_upgrade = kwargs.get('automatic_os_upgrade', None)
        self.auto_os_upgrade_policy = kwargs.get('auto_os_upgrade_policy', None)
