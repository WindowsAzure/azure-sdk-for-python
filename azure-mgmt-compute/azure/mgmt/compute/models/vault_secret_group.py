# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft and contributors.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class VaultSecretGroup(Model):
    """
    Describes a set of certificates which are all in the same Key Vault.

    :param source_vault: Gets or sets the Relative URL of the Key Vault
     containing all of the certificates in VaultCertificates.
    :type source_vault: :class:`SubResource
     <azure.mgmt.compute.models.SubResource>`
    :param vault_certificates: Gets or sets the list of key vault references
     in SourceVault which contain certificates
    :type vault_certificates: list of :class:`VaultCertificate
     <azure.mgmt.compute.models.VaultCertificate>`
    """ 

    _attribute_map = {
        'source_vault': {'key': 'sourceVault', 'type': 'SubResource'},
        'vault_certificates': {'key': 'vaultCertificates', 'type': '[VaultCertificate]'},
    }

    def __init__(self, source_vault=None, vault_certificates=None, **kwargs):
        self.source_vault = source_vault
        self.vault_certificates = vault_certificates
