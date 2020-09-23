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
import pytest
import uuid
import os

from azure.schemaregistry.aio import SchemaRegistryClient
from azure.identity.aio import ClientSecretCredential
from azure.core.exceptions import ClientAuthenticationError, ServiceRequestError, HttpResponseError

from schemaregistry_preparer import SchemaRegistryPreparer
from devtools_testutils import AzureTestCase
from devtools_testutils.azure_testcase import _is_autorest_v3

from azure.core.credentials import AccessToken


class SchemaRegistryAsyncTests(AzureTestCase):

    class AsyncFakeCredential(object):
        async def get_token(self, *scopes, **kwargs):
            return AccessToken('fake_token', 2527537086)

        async def close(self):
            pass

    def create_basic_client(self, client_class, **kwargs):
        # This is the patch for creating client using aio identity

        tenant_id = os.environ.get("AZURE_TENANT_ID", None)
        client_id = os.environ.get("AZURE_CLIENT_ID", None)
        secret = os.environ.get("AZURE_CLIENT_SECRET", None)

        if tenant_id and client_id and secret and self.is_live:
            if _is_autorest_v3(client_class):
                # Create azure-identity class
                from azure.identity.aio import ClientSecretCredential
                credentials = ClientSecretCredential(
                    tenant_id=tenant_id,
                    client_id=client_id,
                    client_secret=secret
                )
            else:
                # Create msrestazure class
                from msrestazure.azure_active_directory import ServicePrincipalCredentials
                credentials = ServicePrincipalCredentials(
                    tenant=tenant_id,
                    client_id=client_id,
                    secret=secret
                )
        else:
            if _is_autorest_v3(client_class):
                credentials = self.AsyncFakeCredential()
                #credentials = self.settings.get_azure_core_credentials()
            else:
                credentials = self.settings.get_credentials()

        # Real client creation
        # FIXME decide what is the final argument for that
        # if self.is_playback():
        #     kwargs.setdefault("polling_interval", 0)
        if _is_autorest_v3(client_class):
            kwargs.setdefault("logging_enable", True)
            client = client_class(
                credential=credentials,
                **kwargs
            )
        else:
            client = client_class(
                credentials=credentials,
                **kwargs
            )

        if self.is_playback():
            try:
                client._config.polling_interval = 0  # FIXME in azure-mgmt-core, make this a kwargs
            except AttributeError:
                pass

        if hasattr(client, "config"):  # Autorest v2
            if self.is_playback():
                client.config.long_running_operation_timeout = 0
            client.config.enable_http_logger = True
        return client

    @SchemaRegistryPreparer()
    async def test_schema_basic_async(self, schemaregistry_endpoint, schemaregistry_group, **kwargs):
        client = self.create_basic_client(SchemaRegistryClient, endpoint=schemaregistry_endpoint)
        async with client:
            schema_name = self.get_resource_name('test-schema-basic-async')
            schema_str = """{"namespace":"example.avro","type":"record","name":"User","fields":[{"name":"name","type":"string"},{"name":"favorite_number","type":["int","null"]},{"name":"favorite_color","type":["string","null"]}]}"""
            serialization_type = "Avro"
            schema_properties = await client.register_schema(schemaregistry_group, schema_name, serialization_type, schema_str)

            assert schema_properties.schema_id is not None
            assert schema_properties.location is not None
            assert schema_properties.location_by_id is not None
            assert schema_properties.version is 1
            assert schema_properties.serialization_type == "Avro"

            returned_schema = await client.get_schema(schema_id=schema_properties.schema_id)

            assert returned_schema.schema_properties.schema_id == schema_properties.schema_id
            assert returned_schema.schema_properties.location is not None
            assert returned_schema.schema_properties.location_by_id is not None
            assert returned_schema.schema_properties.version == 1
            assert returned_schema.schema_properties.serialization_type == "Avro"
            assert returned_schema.schema_content == schema_str

            returned_schema_properties = await client.get_schema_id(schemaregistry_group, schema_name, serialization_type, schema_str)

            assert returned_schema_properties.schema_id == schema_properties.schema_id
            assert returned_schema_properties.location is not None
            assert returned_schema_properties.location_by_id is not None
            assert returned_schema_properties.version == 1
            assert returned_schema_properties.serialization_type == "Avro"
        await client._generated_client._config.credential.close()

    @SchemaRegistryPreparer()
    async def test_schema_update_async(self, schemaregistry_endpoint, schemaregistry_group, **kwargs):
        client = self.create_basic_client(SchemaRegistryClient, endpoint=schemaregistry_endpoint)
        async with client:
            schema_name = self.get_resource_name('test-schema-update-async')
            schema_str = """{"namespace":"example.avro","type":"record","name":"User","fields":[{"name":"name","type":"string"},{"name":"favorite_number","type":["int","null"]},{"name":"favorite_color","type":["string","null"]}]}"""
            serialization_type = "Avro"
            schema_properties = await client.register_schema(schemaregistry_group, schema_name, serialization_type, schema_str)

            assert schema_properties.schema_id is not None
            assert schema_properties.location is not None
            assert schema_properties.location_by_id is not None
            assert schema_properties.version != 0
            assert schema_properties.serialization_type == "Avro"

            schema_str_new = """{"namespace":"example.avro","type":"record","name":"User","fields":[{"name":"name","type":"string"},{"name":"favorite_number","type":["int","null"]},{"name":"favorite_food","type":["string","null"]}]}"""
            new_schema_properties = await client.register_schema(schemaregistry_group, schema_name, serialization_type, schema_str_new)

            assert new_schema_properties.schema_id is not None
            assert new_schema_properties.location is not None
            assert new_schema_properties.location_by_id is not None
            assert new_schema_properties.version == schema_properties.version + 1
            assert new_schema_properties.serialization_type == "Avro"

            new_schema = await client.get_schema(schema_id=new_schema_properties.schema_id)

            assert new_schema.schema_properties.schema_id != schema_properties.schema_id
            assert new_schema.schema_properties.schema_id == new_schema_properties.schema_id
            assert new_schema.schema_properties.location is not None
            assert new_schema.schema_properties.location_by_id is not None
            assert new_schema.schema_content == schema_str_new
            assert new_schema.schema_properties.version == schema_properties.version + 1
            assert new_schema.schema_properties.serialization_type == "Avro"
        await client._generated_client._config.credential.close()

    @SchemaRegistryPreparer()
    async def test_schema_same_twice_async(self, schemaregistry_endpoint, schemaregistry_group, **kwargs):
        client = self.create_basic_client(SchemaRegistryClient, endpoint=schemaregistry_endpoint)
        schema_name = self.get_resource_name('test-schema-twice-async')
        schema_str = """{"namespace":"example.avro","type":"record","name":"User","fields":[{"name":"name","type":"string"},{"name":"age","type":["int","null"]},{"name":"city","type":["string","null"]}]}"""
        serialization_type = "Avro"
        async with client:
            schema_properties = await client.register_schema(schemaregistry_group, schema_name, serialization_type, schema_str)
            schema_properties_second = await client.register_schema(schemaregistry_group, schema_name, serialization_type, schema_str)
            assert schema_properties.schema_id == schema_properties_second.schema_id
        await client._generated_client._config.credential.close()

    @SchemaRegistryPreparer()
    async def test_schema_negative_wrong_credential_async(self, schemaregistry_endpoint, schemaregistry_group, **kwargs):
        credential = ClientSecretCredential(tenant_id="fake", client_id="fake", client_secret="fake")
        client = SchemaRegistryClient(endpoint=schemaregistry_endpoint, credential=credential)
        async with client, credential:
            schema_name = self.get_resource_name('test-schema-negative-async')
            schema_str = """{"namespace":"example.avro","type":"record","name":"User","fields":[{"name":"name","type":"string"},{"name":"favorite_number","type":["int","null"]},{"name":"favorite_color","type":["string","null"]}]}"""
            serialization_type = "Avro"
            with pytest.raises(ClientAuthenticationError):
                await client.register_schema(schemaregistry_group, schema_name, serialization_type, schema_str)

    @SchemaRegistryPreparer()
    async def test_schema_negative_wrong_endpoint_async(self, schemaregistry_endpoint, schemaregistry_group, **kwargs):
        client = self.create_basic_client(SchemaRegistryClient, endpoint="nonexist.servicebus.windows.net")
        async with client:
            schema_name = self.get_resource_name('test-schema-nonexist-async')
            schema_str = """{"namespace":"example.avro","type":"record","name":"User","fields":[{"name":"name","type":"string"},{"name":"favorite_number","type":["int","null"]},{"name":"favorite_color","type":["string","null"]}]}"""
            serialization_type = "Avro"
            with pytest.raises(ServiceRequestError):
                await client.register_schema(schemaregistry_group, schema_name, serialization_type, schema_str)
        await client._generated_client._config.credential.close()

    @SchemaRegistryPreparer()
    async def test_schema_negative_no_schema_async(self, schemaregistry_endpoint, schemaregistry_group, **kwargs):
        client = self.create_basic_client(SchemaRegistryClient, endpoint=schemaregistry_endpoint)
        async with client:
            with pytest.raises(HttpResponseError):
                await client.get_schema('a')

            with pytest.raises(HttpResponseError):
                await client.get_schema('a' * 32)
        await client._generated_client._config.credential.close()
