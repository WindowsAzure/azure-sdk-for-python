# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import functools
import os
import uuid

from azure.keyvault.administration.aio import KeyVaultAccessControlClient
from devtools_testutils import KeyVaultPreparer, ResourceGroupPreparer
import pytest

from _shared.test_case_async import KeyVaultTestCase
from _shared.preparer_async import KeyVaultClientPreparer as _KeyVaultClientPreparer

AccessControlClientPreparer = functools.partial(_KeyVaultClientPreparer, KeyVaultAccessControlClient)


class AccessControlTests(KeyVaultTestCase):
    def __init__(self, *args, **kwargs):
        super(AccessControlTests, self).__init__(*args, **kwargs)
        if self.is_live:
            pytest.skip("test infrastructure can't yet create a Key Vault supporting the RBAC API")

    def get_replayable_uuid(self, replay_value):
        if self.is_live:
            value = str(uuid.uuid4())
            self.scrubber.register_name_pair(value, replay_value)
            return value
        return replay_value

    def get_service_principal_id(self):
        replay_value = "service-principal-id"
        if self.is_live:
            value = os.environ["AZURE_CLIENT_ID"]
            self.scrubber.register_name_pair(value, replay_value)
            return value
        return replay_value

    @ResourceGroupPreparer(random_name_enabled=True)
    @KeyVaultPreparer()
    @AccessControlClientPreparer()
    async def test_list_role_definitions(self, client):
        definitions = []
        async for definition in client.list_role_definitions("/"):
            definitions.append(definition)
        assert len(definitions)

        for definition in definitions:
            assert "/" in definition.assignable_scopes
            assert definition.description is not None
            assert definition.id is not None
            assert definition.name is not None
            assert len(definition.permissions)
            assert definition.role_name is not None
            assert definition.role_type is not None
            assert definition.type is not None

    @ResourceGroupPreparer(random_name_enabled=True)
    @KeyVaultPreparer()
    @AccessControlClientPreparer()
    async def test_role_assignment(self, client):
        scope = "/"
        definitions = []
        async for definition in client.list_role_definitions("/"):
            definitions.append(definition)

        # assign an arbitrary role to the service principal authenticating these requests
        definition = definitions[0]
        principal_id = self.get_service_principal_id()
        name = self.get_replayable_uuid("some-uuid")

        created = await client.create_role_assignment(scope, name, definition.id, principal_id)
        assert created.name == name
        assert created.principal_id == principal_id
        assert created.role_definition_id == definition.id
        assert created.scope == scope

        # should be able to get the new assignment
        got = await client.get_role_assignment(scope, name)
        assert got.name == name
        assert got.principal_id == principal_id
        assert got.role_definition_id == definition.id
        assert got.scope == scope

        # new assignment should be in the list of all assignments
        matching_assignments = []
        async for assignment in client.list_role_assignments(scope):
            if assignment.assignment_id == created.assignment_id:
                matching_assignments.append(assignment)
        assert len(matching_assignments) == 1

        # delete the assignment
        deleted = await client.delete_role_assignment(scope, created.name)
        assert deleted.name == created.name
        assert deleted.assignment_id == created.assignment_id
        assert deleted.scope == scope
        assert deleted.role_definition_id == created.role_definition_id

        async for assignment in client.list_role_assignments(scope):
            assert assignment.assignment_id != created.assignment_id, "the role assignment should have been deleted"
