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


class UpdateAutoRenewRequest(Model):
    """Request parameters to update auto renew for support product.

    :param auto_renew: Request parameters to update auto renew policy a
     product. Possible values include: 'true', 'false'
    :type auto_renew: str or ~azure.mgmt.billing.models.UpdateAutoRenew
    """

    _attribute_map = {
        'auto_renew': {'key': 'autoRenew', 'type': 'str'},
    }

    def __init__(self, *, auto_renew=None, **kwargs) -> None:
        super(UpdateAutoRenewRequest, self).__init__(**kwargs)
        self.auto_renew = auto_renew
