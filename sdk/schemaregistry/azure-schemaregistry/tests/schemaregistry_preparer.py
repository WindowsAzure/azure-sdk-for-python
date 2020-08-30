# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the ""Software""), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
# --------------------------------------------------------------------------

import functools
import hashlib
import os
from collections import namedtuple

from azure.identity import ClientSecretCredential
from azure_devtools.scenario_tests.exceptions import AzureTestError
from devtools_testutils import (
    ResourceGroupPreparer, AzureMgmtPreparer, FakeResource
)


SCHEMA_REGISTRY_ENDPOINT_PARAM = "schemaregistry_endpoint"
SCHEMA_REGISTRY_GROUP_PARAM = "schemaregistry_group"
SCHEMA_REGISTRY_TENANT_ID_PARAM = "schemaregistry_tenant_id"
SCHEMA_REGISTRY_CLIENT_ID_PARAM = "schemaregistry_client_id"
SCHEMA_REGISTRY_CLIENT_SECRET_PARAM = "schemaregistry_client_secret"
SCHEMA_REGISTRY_ENDPOINT_ENV_KEY_NAME = 'SCHEMA_REGISTRY_ENDPOINT'
SCHEMA_REGISTRY_GROUP_ENV_KEY_NAME = 'SCHEMA_REGISTRY_GROUP'
AZURE_TENANT_ID_ENV_KEY_NAME = 'SCHEMA_REGISTRY_AZURE_TENANT_ID'
AZURE_CLIENT_ID_ENV_KEY_NAME = 'SCHEMA_REGISTRY_AZURE_CLIENT_ID'
AZURE_CLIENT_SECRET_ENV_KEY_NAME = 'SCHEMA_REGISTRY_AZURE_CLIENT_SECRET'


class SchemaRegistryNamespacePreparer(AzureMgmtPreparer):
    # TODO: SR doesn't have mgmt package
    def __init__(self):
        pass

    def create_resource(self, name, **kwargs):
        pass

    def remove_resource(self, name, **kwargs):
        pass


class SchemaRegistryPreparer(AzureMgmtPreparer):
    def __init__(
        self,
        name_prefix=''
    ):
        super(SchemaRegistryPreparer, self).__init__(name_prefix, 24)

    def create_resource(self, name, **kwargs):
        # TODO: right now the endpoint/group is fixed, as there is no way to create/delete resources using mgmt api, in the future we should be able to dynamically create and remove resources
        return {
            SCHEMA_REGISTRY_ENDPOINT_PARAM: os.environ[SCHEMA_REGISTRY_ENDPOINT_ENV_KEY_NAME],
            SCHEMA_REGISTRY_GROUP_PARAM: os.environ[SCHEMA_REGISTRY_GROUP_ENV_KEY_NAME],
            SCHEMA_REGISTRY_TENANT_ID_PARAM: os.environ[AZURE_TENANT_ID_ENV_KEY_NAME],
            SCHEMA_REGISTRY_CLIENT_ID_PARAM: os.environ[AZURE_CLIENT_ID_ENV_KEY_NAME],
            SCHEMA_REGISTRY_CLIENT_SECRET_PARAM: os.environ[AZURE_CLIENT_SECRET_ENV_KEY_NAME]
        }

    def remove_resource(self, name, **kwargs):
        pass
