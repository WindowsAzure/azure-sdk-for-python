# coding: utf-8

# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------

"""
USAGE:
    python test_samples.py

    Set the environment variables with your own values before running the samples.
    See independent sample files to check what env variables must be set.
"""


import subprocess
import sys
import os
import pytest
from testcase import FormRecognizerTest, GlobalFormRecognizerAccountPreparer

def _setenv(key, val):
    os.environ[key] = os.getenv(val) or os.environ[key]

def run(cmd):
    os.environ['PYTHONUNBUFFERED'] = "1"
    _setenv('CUSTOM_TRAINED_MODEL_ID', 'AZURE_FORM_RECOGNIZER_CUSTOM_TRAINED_MODEL_ID')
    _setenv('CONTAINER_SAS_URL', 'AZURE_FORM_RECOGNIZER_STORAGE_CONTAINER_SAS_URL')
    proc = subprocess.Popen(cmd,
        stdout = subprocess.PIPE,
        stderr = subprocess.STDOUT,
    )
    stdout, stderr = proc.communicate()

    return proc.returncode, stdout, stderr

def run(cmd):
    os.environ['PYTHONUNBUFFERED'] = "1"
    proc = subprocess.Popen(cmd,
        stdout = subprocess.PIPE,
        stderr = subprocess.STDOUT,
    )
    stdout, stderr = proc.communicate()
 
    return proc.returncode, stdout, stderr

def _test_file(file_name, account, key, root_dir='./samples/async_samples'):
    os.environ['AZURE_FORM_RECOGNIZER_ENDPOINT'] = account
    os.environ['AZURE_FORM_RECOGNIZER_KEY'] = key
    code, _, err = run([sys.executable, root_dir + '/' + file_name])
    print(_)
    assert code == 0
    assert err is None


class TestSamplesAsync(FormRecognizerTest):
    # Async sample tests
    @pytest.mark.live_test_only
    @GlobalFormRecognizerAccountPreparer()
    def test_sample_authentication_async(self, resource_group, location, form_recognizer_account, form_recognizer_account_key):
        _test_file('sample_authentication_async.py', form_recognizer_account, form_recognizer_account_key)

    @pytest.mark.live_test_only
    @GlobalFormRecognizerAccountPreparer()
    def test_sample_get_bounding_boxes_async(self, resource_group, location, form_recognizer_account, form_recognizer_account_key):
        _test_file('sample_get_bounding_boxes_async.py', form_recognizer_account, form_recognizer_account_key)

    @pytest.mark.live_test_only
    @GlobalFormRecognizerAccountPreparer()
    def test_sample_manage_custom_models_async(self, resource_group, location, form_recognizer_account, form_recognizer_account_key):
        _test_file('sample_manage_custom_models_async.py', form_recognizer_account, form_recognizer_account_key)

    @pytest.mark.live_test_only
    @GlobalFormRecognizerAccountPreparer()
    def test_sample_recognize_content_async(self, resource_group, location, form_recognizer_account, form_recognizer_account_key):
        _test_file('sample_recognize_content_async.py', form_recognizer_account, form_recognizer_account_key)

    @pytest.mark.live_test_only
    @GlobalFormRecognizerAccountPreparer()
    def test_sample_recognize_custom_forms_async(self, resource_group, location, form_recognizer_account, form_recognizer_account_key):
        _test_file('sample_recognize_custom_forms_async.py', form_recognizer_account, form_recognizer_account_key)

    @pytest.mark.live_test_only
    @GlobalFormRecognizerAccountPreparer()
    def test_sample_recognize_receipts_from_url_async(self, resource_group, location, form_recognizer_account, form_recognizer_account_key):
        _test_file('sample_recognize_receipts_from_url_async.py', form_recognizer_account, form_recognizer_account_key)

    @pytest.mark.live_test_only
    @GlobalFormRecognizerAccountPreparer()
    def test_sample_recognize_receipts_async(self, resource_group, location, form_recognizer_account, form_recognizer_account_key):
        _test_file('sample_recognize_receipts_async.py', form_recognizer_account, form_recognizer_account_key)

    @pytest.mark.live_test_only
    @GlobalFormRecognizerAccountPreparer()
    def test_sample_train_model_with_labels_async(self, resource_group, location, form_recognizer_account, form_recognizer_account_key):
        _test_file('sample_train_model_with_labels_async.py', form_recognizer_account, form_recognizer_account_key)

    @pytest.mark.live_test_only
    @GlobalFormRecognizerAccountPreparer()
    def test_sample_train_model_without_labels_async(self, resource_group, location, form_recognizer_account, form_recognizer_account_key):
        _test_file('sample_train_model_without_labels_async.py', form_recognizer_account, form_recognizer_account_key)

