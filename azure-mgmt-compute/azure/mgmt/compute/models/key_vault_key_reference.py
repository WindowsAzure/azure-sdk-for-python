# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class KeyVaultKeyReference(Model):
    """
    Describes a reference to Key Vault Key

    :param key_url: Gets or sets the URL referencing a key in a Key Vault.
    :type key_url: str
    :param source_vault: Gets or sets the Relative URL of the Key Vault
     containing the key
    :type source_vault: :class:`SubResource
     <computemanagementclient.models.SubResource>`
    """ 

    _validation = {
        'key_url': {'required': True},
        'source_vault': {'required': True},
    }

    _attribute_map = {
        'key_url': {'key': 'keyUrl', 'type': 'str'},
        'source_vault': {'key': 'sourceVault', 'type': 'SubResource'},
    }

    def __init__(self, key_url, source_vault):
        self.key_url = key_url
        self.source_vault = source_vault
