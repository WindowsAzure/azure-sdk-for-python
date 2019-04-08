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


class VaultCertificate(Model):
    """Describes a single certificate reference in a Key Vault, and where the
    certificate should reside on the VM.

    :param certificate_url: This is the URL of a certificate that has been
     uploaded to Key Vault as a secret. For adding a secret to the Key Vault,
     see [Add a key or secret to the key
     vault](https://docs.microsoft.com/azure/key-vault/key-vault-get-started/#add).
     In this case, your certificate needs to be It is the Base64 encoding of
     the following JSON Object which is encoded in UTF-8: <br><br> {<br>
     "data":"<Base64-encoded-certificate>",<br>  "dataType":"pfx",<br>
     "password":"<pfx-file-password>"<br>}
    :type certificate_url: str
    :param certificate_store: For Windows VMs, specifies the certificate store
     on the Virtual Machine to which the certificate should be added. The
     specified certificate store is implicitly in the LocalMachine account.
     <br><br>For Linux VMs, the certificate file is placed under the
     /var/lib/waagent directory, with the file name
     &lt;UppercaseThumbprint&gt;.crt for the X509 certificate file and
     &lt;UppercaseThumbprint&gt;.prv for private key. Both of these files are
     .pem formatted.
    :type certificate_store: str
    """

    _attribute_map = {
        'certificate_url': {'key': 'certificateUrl', 'type': 'str'},
        'certificate_store': {'key': 'certificateStore', 'type': 'str'},
    }

    def __init__(self, *, certificate_url: str=None, certificate_store: str=None, **kwargs) -> None:
        super(VaultCertificate, self).__init__(**kwargs)
        self.certificate_url = certificate_url
        self.certificate_store = certificate_store
