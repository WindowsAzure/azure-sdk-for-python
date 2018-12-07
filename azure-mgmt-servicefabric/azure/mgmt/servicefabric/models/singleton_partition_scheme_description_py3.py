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

from .partition_scheme_description_py3 import PartitionSchemeDescription


class SingletonPartitionSchemeDescription(PartitionSchemeDescription):
    """Describes the partition scheme of a singleton-partitioned, or
    non-partitioned service.

    All required parameters must be populated in order to send to Azure.

    :param partition_scheme: Required. Constant filled by server.
    :type partition_scheme: str
    """

    _validation = {
        'partition_scheme': {'required': True},
    }

    _attribute_map = {
        'partition_scheme': {'key': 'PartitionScheme', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(SingletonPartitionSchemeDescription, self).__init__(**kwargs)
        self.partition_scheme = 'Singleton'
