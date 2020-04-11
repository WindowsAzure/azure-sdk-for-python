
# coding: utf-8
# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------

from datetime import datetime, timedelta
import os
import pytest
import re
from azure.core.credentials import AzureKeyCredential
from azure.storage.blob import ContainerSasPermissions, generate_container_sas, ContainerClient
from devtools_testutils import (
    AzureTestCase,
    AzureMgmtPreparer,
    FakeResource,
    ResourceGroupPreparer,
)
from devtools_testutils.cognitiveservices_testcase import CognitiveServicesAccountPreparer
from devtools_testutils.storage_testcase import StorageAccountPreparer
from azure_devtools.scenario_tests import ReplayableTest


class FormRecognizerTest(AzureTestCase):
    FILTER_HEADERS = ReplayableTest.FILTER_HEADERS + ['Ocp-Apim-Subscription-Key']

    def __init__(self, method_name):
        super(FormRecognizerTest, self).__init__(method_name)
        # URL samples
        self.receipt_url_jpg = "https://raw.githubusercontent.com/Azure/azure-sdk-for-python/tree/master/sdk/formrecognizer/azure-ai-formrecognizer/tests/sample_forms/receipt/contoso-allinone.jpg"
        self.receipt_url_png = "https://raw.githubusercontent.com/Azure/azure-sdk-for-python/tree/master/sdk/formrecognizer/azure-ai-formrecognizer/tests/sample_forms/receipt/contoso-receipt.png"
        self.invoice_url_pdf = "https://raw.githubusercontent.com/Azure/azure-sdk-for-python/tree/master/sdk/formrecognizer/azure-ai-formrecognizer/tests/sample_forms/forms/Invoice_1.pdf"
        self.form_url_jpg = "https://raw.githubusercontent.com/Azure/azure-sdk-for-python/tree/master/sdk/formrecognizer/azure-ai-formrecognizer/tests/sample_forms/forms/Form_1.pdf"

        # file stream samples
        self.receipt_jpg = os.path.abspath(os.path.join(os.path.abspath(__file__), "..", "./sample_forms/receipt/contoso-allinone.jpg"))
        self.receipt_png = os.path.abspath(os.path.join(os.path.abspath(__file__), "..", "./sample_forms/receipt/contoso-receipt.png"))
        self.invoice_pdf = os.path.abspath(os.path.join(os.path.abspath(__file__), "..", "./sample_forms/forms/Invoice_1.pdf"))
        self.form_jpg = os.path.abspath(os.path.join(os.path.abspath(__file__), "..", "./sample_forms/forms/Form_1.jpg"))
        self.unsupported_content_py = os.path.abspath(os.path.join(os.path.abspath(__file__), "..", "./conftest.py"))

    def assertModelTransformCorrect(self, model, actual, unlabeled=False):
        self.assertEqual(model.model_id, actual.model_info.model_id)
        self.assertEqual(model.created_on, actual.model_info.created_date_time)
        self.assertEqual(model.last_updated_on, actual.model_info.last_updated_date_time)
        self.assertEqual(model.status, actual.model_info.status)
        self.assertEqual(model.errors, actual.train_result.errors)
        for m, a in zip(model.training_documents, actual.train_result.training_documents):
            self.assertEqual(m.document_name, a.document_name)
            if m.errors and a.errors:
                self.assertEqual(m.errors, a.errors)
            self.assertEqual(m.page_count, a.pages)
            self.assertEqual(m.status, a.status)

        if unlabeled:
            if actual.keys.clusters:
                for cluster_id, fields in actual.keys.clusters.items():
                    self.assertEqual(cluster_id, model.models[int(cluster_id)].form_type[-1])
                    for field_idx, model_field in model.models[int(cluster_id)].fields.items():
                        self.assertIn(model_field.label, fields)

        else:
            if actual.train_result:
                if actual.train_result.fields:
                    for a in actual.train_result.fields:
                        self.assertEqual(model.models[0].fields[a.field_name].name, a.field_name)
                        self.assertEqual(model.models[0].fields[a.field_name].accuracy, a.accuracy)
                    self.assertEqual(model.models[0].form_type, "form-"+model.model_id)
                    self.assertEqual(model.models[0].accuracy, actual.train_result.average_model_accuracy)

    def assertFormPagesTransformCorrect(self, pages, actual_read, page_result=None):
        for page, actual_page in zip(pages, actual_read):
            self.assertEqual(page.page_number, actual_page.page)
            self.assertEqual(page.text_angle, actual_page.angle)
            self.assertEqual(page.width, actual_page.width)
            self.assertEqual(page.height, actual_page.height)
            self.assertEqual(page.unit, actual_page.unit)

            for p, a in zip(page.lines, actual_page.lines):
                self.assertEqual(p.text, a.text)
                self.assertBoundingBoxTransformCorrect(p.bounding_box, a.bounding_box)
                for wp, wa, in zip(p.words, a.words):
                    self.assertEqual(wp.text, wa.text)
                    self.assertEqual(wp.confidence, wa.confidence)
                    self.assertBoundingBoxTransformCorrect(wp.bounding_box, wa.bounding_box)

        if page_result:
            for page, actual_page in zip(pages, page_result):
                self.assertTablesTransformCorrect(page.tables, actual_page.tables, actual_read)

    def assertBoundingBoxTransformCorrect(self, box, actual):
        self.assertEqual(box[0].x, actual[0])
        self.assertEqual(box[0].y, actual[1])
        self.assertEqual(box[1].x, actual[2])
        self.assertEqual(box[1].y, actual[3])
        self.assertEqual(box[2].x, actual[4])
        self.assertEqual(box[2].y, actual[5])
        self.assertEqual(box[3].x, actual[6])
        self.assertEqual(box[3].y, actual[7])

    def assertTextContentTransformCorrect(self, field_elements, actual_elements, read_result):
        for receipt, actual in zip(field_elements, actual_elements):
            nums = [int(s) for s in re.findall(r'\d+', actual)]
            read, line, word = nums[0:3]
            text_element = read_result[read].lines[line].words[word]
            self.assertEqual(receipt.text, text_element.text)
            self.assertEqual(receipt.confidence, text_element.confidence)
            self.assertBoundingBoxTransformCorrect(receipt.bounding_box, text_element.bounding_box)

    def assertFormFieldTransformCorrect(self, receipt_field, actual_field, read_results=None):
        if actual_field is None:
            return
        field_type = actual_field.type
        if field_type == "string":
            self.assertEqual(receipt_field.value, actual_field.value_string)
        if field_type == "number":
            self.assertEqual(receipt_field.value, actual_field.value_number)
        if field_type == "integer":
            self.assertEqual(receipt_field.value, actual_field.value_integer)
        if field_type == "date":
            self.assertEqual(receipt_field.value, actual_field.value_date)
        if field_type == "phoneNumber":
            self.assertEqual(receipt_field.value, actual_field.value_phone_number)
        if field_type == "time":
            self.assertEqual(receipt_field.value, actual_field.value_time)

        self.assertBoundingBoxTransformCorrect(receipt_field.value_data.bounding_box, actual_field.bounding_box)
        self.assertEqual(receipt_field.value_data.text, actual_field.text)
        self.assertEqual(receipt_field.confidence, actual_field.confidence)
        self.assertEqual(receipt_field.page_number, actual_field.page)
        if read_results:
            self.assertTextContentTransformCorrect(
                receipt_field.value_data.text_content,
                actual_field.elements,
                read_results
            )

    def assertReceiptItemsTransformCorrect(self, items, actual_items, read_results=None):
        actual = actual_items.value_array

        for r, a in zip(items, actual):
            self.assertFormFieldTransformCorrect(r.name, a.value_object.get("Name"), read_results)
            self.assertFormFieldTransformCorrect(r.quantity, a.value_object.get("Quantity"), read_results)
            self.assertFormFieldTransformCorrect(r.total_price, a.value_object.get("TotalPrice"), read_results)
            self.assertFormFieldTransformCorrect(r.price, a.value_object.get("Price"), read_results)

    def assertTablesTransformCorrect(self, layout, actual_layout, read_results=None):
        for table, actual_table in zip(layout, actual_layout):
            self.assertEqual(table.row_count, actual_table.rows)
            self.assertEqual(table.column_count, actual_table.columns)
            for cell, actual_cell in zip(table.cells, actual_table.cells):
                self.assertEqual(cell.text, actual_cell.text)
                self.assertEqual(cell.row_index, actual_cell.row_index)
                self.assertEqual(cell.column_index, actual_cell.column_index)
                self.assertEqual(cell.row_span, actual_cell.row_span if actual_cell.row_span is not None else 1)
                self.assertEqual(cell.column_span, actual_cell.column_span if actual_cell.column_span is not None else 1)
                self.assertEqual(cell.confidence, actual_cell.confidence)
                self.assertEqual(cell.is_header, actual_cell.is_header if actual_cell.is_header is not None else False)
                self.assertEqual(cell.is_footer, actual_cell.is_footer if actual_cell.is_footer is not None else False)
                self.assertBoundingBoxTransformCorrect(cell.bounding_box, actual_cell.bounding_box)
                self.assertTextContentTransformCorrect(cell.text_content, actual_cell.elements, read_results)

    def assertReceiptItemsHasValues(self, items, page_number, include_text_content):
        for item in items:
            self.assertBoundingBoxHasPoints(item.name.value_data.bounding_box)
            self.assertIsNotNone(item.name.confidence)
            self.assertIsNotNone(item.name.value_data.text)
            self.assertBoundingBoxHasPoints(item.quantity.value_data.bounding_box)
            self.assertIsNotNone(item.quantity.confidence)
            self.assertIsNotNone(item.quantity.value_data.text)
            self.assertBoundingBoxHasPoints(item.total_price.value_data.bounding_box)
            self.assertIsNotNone(item.total_price.confidence)
            self.assertIsNotNone(item.total_price.value_data.text)

            if include_text_content:
                self.assertTextContentHasValues(item.name.value_data.text_content, page_number)
                self.assertTextContentHasValues(item.name.value_data.text_content, page_number)
                self.assertTextContentHasValues(item.name.value_data.text_content, page_number)

    def assertBoundingBoxHasPoints(self, box):
        if box is None:
            return
        self.assertIsNotNone(box[0].x)
        self.assertIsNotNone(box[0].y)
        self.assertIsNotNone(box[1].x)
        self.assertIsNotNone(box[1].y)
        self.assertIsNotNone(box[2].x)
        self.assertIsNotNone(box[2].y)
        self.assertIsNotNone(box[3].x)
        self.assertIsNotNone(box[3].y)

    def assertFormPagesHasValues(self, pages):
        for page in pages:
            self.assertIsNotNone(page.text_angle)
            self.assertIsNotNone(page.height)
            self.assertIsNotNone(page.unit)
            self.assertIsNotNone(page.width)
            self.assertIsNotNone(page.page_number)
            if page.lines:
                for line in page.lines:
                    self.assertIsNotNone(line.text)
                    self.assertIsNotNone(line.page_number)
                    self.assertBoundingBoxHasPoints(line.bounding_box)
                    for word in line.words:
                        self.assertFormWordHasValues(word, page.page_number)

            if page.tables:
                for table in page.tables:
                    self.assertIsNotNone(table.row_count)
                    self.assertIsNotNone(table.column_count)
                    for cell in table.cells:
                        self.assertIsNotNone(cell.text)
                        self.assertIsNotNone(cell.row_index)
                        self.assertIsNotNone(cell.column_index)
                        self.assertIsNotNone(cell.row_span)
                        self.assertIsNotNone(cell.column_span)
                        self.assertBoundingBoxHasPoints(cell.bounding_box)
                        self.assertTextContentHasValues(cell.text_content, page.page_number)

    def assertFormWordHasValues(self, word, page_number):
        self.assertIsNotNone(word.confidence)
        self.assertIsNotNone(word.text)
        self.assertBoundingBoxHasPoints(word.bounding_box)
        self.assertEqual(word.page_number, page_number)

    def assertTextContentHasValues(self, elements, page_number):
        if elements is None:
            return
        for word in elements:
            self.assertFormWordHasValues(word, page_number)


class GlobalResourceGroupPreparer(AzureMgmtPreparer):
    def __init__(self):
        super(GlobalResourceGroupPreparer, self).__init__(
            name_prefix='',
            random_name_length=42
        )

    def create_resource(self, name, **kwargs):
        rg = FormRecognizerTest._RESOURCE_GROUP
        if self.is_live:
            self.test_class_instance.scrubber.register_name_pair(
                rg.name,
                "rgname"
            )
        else:
            rg = FakeResource(
                name="rgname",
                id="/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rgname"
            )

        return {
            'location': 'westus2',
            'resource_group': rg,
        }


class GlobalFormRecognizerAccountPreparer(AzureMgmtPreparer):
    def __init__(self):
        super(GlobalFormRecognizerAccountPreparer, self).__init__(
            name_prefix='',
            random_name_length=42
        )

    def create_resource(self, name, **kwargs):
        form_recognizer_account = FormRecognizerTest._FORM_RECOGNIZER_ACCOUNT
        return {
            'location': 'westus2',
            'resource_group': FormRecognizerTest._RESOURCE_GROUP,
            'form_recognizer_account': form_recognizer_account,
            'form_recognizer_account_key': FormRecognizerTest._FORM_RECOGNIZER_KEY,
        }


class GlobalTrainingAccountPreparer(AzureMgmtPreparer):
    def __init__(self, client_cls, client_kwargs={}, **kwargs):
        super(GlobalTrainingAccountPreparer, self).__init__(
            name_prefix='',
            random_name_length=42
        )
        self.client_kwargs = client_kwargs
        self.client_cls = client_cls

    def create_resource(self, name, **kwargs):
        client, container_sas_url = self.create_form_client_and_container_sas_url(**kwargs)
        if self.is_live:
            self.test_class_instance.scrubber.register_name_pair(
                container_sas_url,
                "containersasurl"
            )
        return {"client": client,
                "container_sas_url": container_sas_url}

    def create_form_client_and_container_sas_url(self, **kwargs):
        form_recognizer_account = self.client_kwargs.pop("form_recognizer_account", None)
        if form_recognizer_account is None:
            form_recognizer_account = kwargs.pop("form_recognizer_account")

        form_recognizer_account_key = self.client_kwargs.pop("form_recognizer_account_key", None)
        if form_recognizer_account_key is None:
            form_recognizer_account_key = kwargs.pop("form_recognizer_account_key")

        storage_account = self.client_kwargs.pop("storage_account", None)
        if storage_account is None:
            storage_account = kwargs.pop("storage_account")

        storage_account_key = self.client_kwargs.pop("storage_account_key", None)
        if storage_account_key is None:
            storage_account_key = kwargs.pop("storage_account_key")

        if self.is_live:
            container_name = self.resource_random_name.replace("_", "-")  # container names can't have underscore
            container_client = ContainerClient(storage_account.primary_endpoints.blob, container_name,
                                               storage_account_key)
            container_client.create_container()

            training_path = os.path.abspath(os.path.join(os.path.abspath(__file__), "..", "./sample_forms/training/"))
            for path, folder, files in os.walk(training_path):
                for document in files:
                    with open(os.path.join(path, document), "rb") as data:
                        if document == "Form_6.jpg":
                            document = "subfolder/Form_6.jpg"  # create virtual subfolder in container
                        container_client.upload_blob(name=document, data=data)

            sas_token = generate_container_sas(
                storage_account.name,
                container_name,
                storage_account_key,
                permission=ContainerSasPermissions.from_string("rl"),
                expiry=datetime.utcnow() + timedelta(hours=1)
            )

            container_sas_url = storage_account.primary_endpoints.blob + container_name + "?" + sas_token

        else:
            container_sas_url = "containersasurl"

        return self.client_cls(
            form_recognizer_account,
            AzureKeyCredential(form_recognizer_account_key),
            **self.client_kwargs
        ), container_sas_url


class GlobalFormAndStorageAccountPreparer(AzureMgmtPreparer):
    def __init__(self):
        super(GlobalFormAndStorageAccountPreparer, self).__init__(
            name_prefix='',
            random_name_length=42
        )

    def create_resource(self, name, **kwargs):
        form_recognizer_and_storage_account = FormRecognizerTest._FORM_RECOGNIZER_ACCOUNT
        return {
            'location': 'westus2',
            'resource_group': FormRecognizerTest._RESOURCE_GROUP,
            'form_recognizer_account': form_recognizer_and_storage_account,
            'form_recognizer_account_key': FormRecognizerTest._FORM_RECOGNIZER_KEY,
            'storage_account': FormRecognizerTest._STORAGE_ACCOUNT,
            'storage_account_key': FormRecognizerTest._STORAGE_KEY
        }


@pytest.fixture(scope="session")
def form_recognizer_account():
    test_case = AzureTestCase("__init__")
    rg_preparer = ResourceGroupPreparer(random_name_enabled=True, name_prefix='pycog')
    form_recognizer_preparer = CognitiveServicesAccountPreparer(
        random_name_enabled=True,
        kind="formrecognizer",
        name_prefix='pycog',
        location="centraluseuap"
    )

    try:
        rg_name, rg_kwargs = rg_preparer._prepare_create_resource(test_case)
        FormRecognizerTest._RESOURCE_GROUP = rg_kwargs['resource_group']
        try:
            form_recognizer_name, form_recognizer_kwargs = form_recognizer_preparer._prepare_create_resource(test_case, **rg_kwargs)
            FormRecognizerTest._FORM_RECOGNIZER_ACCOUNT = form_recognizer_kwargs['cognitiveservices_account']
            FormRecognizerTest._FORM_RECOGNIZER_KEY = form_recognizer_kwargs['cognitiveservices_account_key']
            yield
        finally:
            form_recognizer_preparer.remove_resource(
                form_recognizer_name,
                resource_group=rg_kwargs['resource_group']
            )
            FormRecognizerTest._FORM_RECOGNIZER_ACCOUNT = None
            FormRecognizerTest._FORM_RECOGNIZER_KEY = None
    finally:
        rg_preparer.remove_resource(rg_name)
        FormRecognizerTest._RESOURCE_GROUP = None


@pytest.fixture(scope="session")
def form_recognizer_and_storage_account():
    test_case = AzureTestCase("__init__")
    rg_preparer = ResourceGroupPreparer(random_name_enabled=True, name_prefix='pycog')
    form_recognizer_preparer = CognitiveServicesAccountPreparer(
        random_name_enabled=True,
        kind="formrecognizer",
        name_prefix='pycog',
        location="centraluseuap"
    )
    storage_account_preparer = StorageAccountPreparer(
        random_name_enabled=True,
        name_prefix='pycog'
    )

    try:
        rg_name, rg_kwargs = rg_preparer._prepare_create_resource(test_case)
        FormRecognizerTest._RESOURCE_GROUP = rg_kwargs['resource_group']
        try:
            form_recognizer_name, form_recognizer_kwargs = form_recognizer_preparer._prepare_create_resource(
                test_case, **rg_kwargs)
            FormRecognizerTest._FORM_RECOGNIZER_ACCOUNT = form_recognizer_kwargs['cognitiveservices_account']
            FormRecognizerTest._FORM_RECOGNIZER_KEY = form_recognizer_kwargs['cognitiveservices_account_key']

            storage_name, storage_kwargs = storage_account_preparer._prepare_create_resource(test_case, **rg_kwargs)
            storage_account = storage_kwargs['storage_account']
            storage_key = storage_kwargs['storage_account_key']

            FormRecognizerTest._STORAGE_ACCOUNT = storage_account
            FormRecognizerTest._STORAGE_KEY = storage_key
            yield
        finally:
            form_recognizer_preparer.remove_resource(
                form_recognizer_name,
                resource_group=rg_kwargs['resource_group']
            )
            FormRecognizerTest._FORM_RECOGNIZER_ACCOUNT = None
            FormRecognizerTest._FORM_RECOGNIZER_KEY = None
            storage_account_preparer.remove_resource(
                storage_name,
                resource_group=rg_kwargs['resource_group']
            )
            FormRecognizerTest._STORAGE_ACCOUNT = None
            FormRecognizerTest._STORAGE_KEY = None
    finally:
        rg_preparer.remove_resource(rg_name)
        FormRecognizerTest._RESOURCE_GROUP = None
