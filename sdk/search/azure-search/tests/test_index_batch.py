# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------

import pytest

from azure.search.index._generated.models import IndexAction

from azure.search import IndexBatch

METHOD_NAMES = [
    'add_upload_documents',
    'add_delete_documents',
    'add_merge_documents',
    'add_merge_or_upload_documents'
]

METHOD_MAP = dict(zip(METHOD_NAMES, ['upload', 'delete', 'merge', 'mergeOrUpload']))

class TestIndexBatch(object):

    def test_init(self):
        batch = IndexBatch()
        assert batch.actions == []

    def test_repr(self):
        batch = IndexBatch()
        assert repr(batch) == "<IndexBatch [0 actions]>"

        batch._actions = [1,2,3]
        assert repr(batch) == "<IndexBatch [3 actions]>"

    def test_actions_returns_list_copy(self):
        batch = IndexBatch()
        batch.actions.extend([1,2,3])
        assert type(batch.actions) is list
        assert batch.actions == []
        assert batch.actions is not batch._actions

    @pytest.mark.parametrize('method_name', METHOD_NAMES)
    def test_add_method(self, method_name):
        batch = IndexBatch()

        method = getattr(batch, method_name)

        method("doc1")
        assert len(batch.actions) == 1

        method("doc2", "doc3")
        assert len(batch.actions) == 3

        method(["doc4", "doc5"])
        assert len(batch.actions) == 5

        method(("doc6", "doc7"))
        assert len(batch.actions) == 7

        assert all(action.action_type == METHOD_MAP[method_name] for action in batch.actions)
        assert all(type(action) == IndexAction for action in batch.actions)

        expected = ["doc{}".format(i) for i in range(1,8)]
        assert [action.additional_properties for action in batch.actions] == expected
