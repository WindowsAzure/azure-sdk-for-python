from azure.identity import DefaultAzureCredential, KnownAuthorities

class KeyVaultBase:
    credential_type = DefaultAzureCredential
    host_alias_map = {
        'AzureChinaCloud': KnownAuthorities.AZURE_CHINA,
        'AzureGermanCloud': KnownAuthorities.AZURE_GERMANY,
        'AzureUSGovernment': KnownAuthorities.AZURE_GOVERNMENT,
        'AzureCloud': KnownAuthorities.AZURE_PUBLIC_CLOUD,
    }

    def get_authority_url(self, alias, default=KnownAuthorities.AZURE_PUBLIC_CLOUD):
        if alias in self.host_alias_map:
            return self.host_alias_map[alias]
        return default

    # Instantiate a default credential based on the credential_type
    def get_default_credential(self, authority_host_alias):
        authority_host = self.get_authority_url(authority_host_alias)
        credential = self.credential_type(authority=authority_host)
        return credential
