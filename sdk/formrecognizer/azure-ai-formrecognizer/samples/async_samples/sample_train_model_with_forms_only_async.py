# coding: utf-8

# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------

"""
FILE: sample_train_model_with_forms_only_async.py

DESCRIPTION:
    This sample demonstrates how to train a model with forms only. See sample_recognize_custom_forms_async.py
    to recognize forms with your custom model.
USAGE:
    python sample_train_model_with_forms_only_async.py

    Set the environment variables with your own values before running the sample:
    1) AZURE_FORM_RECOGNIZER_ENDPOINT - the endpoint to your Cognitive Services resource.
    2) AZURE_FORM_RECOGNIZER_KEY - your Form Recognizer API key
    3) CONTAINER_SAS_URL - The shared access signature (SAS) Url of your Azure Blob Storage container with your forms.
                      See https://docs.microsoft.com/en-us/azure/cognitive-services/form-recognizer/quickstarts/label-tool#connect-to-the-sample-labeling-tool
                      for more detailed descriptions on how to get it.
"""

import os
import asyncio


class TrainUnlabeledModelSampleAsync(object):

    endpoint = os.environ["AZURE_FORM_RECOGNIZER_ENDPOINT"]
    key = os.environ["AZURE_FORM_RECOGNIZER_KEY"]
    container_sas_url = os.environ["CONTAINER_SAS_URL"]

    async def train_unlabeled_model(self):
        # [START training_async]
        from azure.ai.formrecognizer.aio import FormTrainingClient
        from azure.core.credentials import AzureKeyCredential

        async with FormTrainingClient(
            self.endpoint, AzureKeyCredential(self.key)
        ) as form_training_client:

            # Default for train_model is `use_labels=False`
            model = await form_training_client.train_model(self.container_sas_url)

            # Custom model information
            print("Model ID: {}".format(model.model_id))
            print("Status: {}".format(model.status))
            print("Created on: {}".format(model.created_on))
            print("Last modified: {}".format(model.last_modified))

            print("Recognized fields:")
            # looping through the submodels, which contains the fields they were trained on
            # Since the given training documents are unlabeled, we still group them but they do not have a label.
            for submodel in model.models:
                # Since the training data is unlabeled, we are unable to return the accuracy of this model
                for name, field in submodel.fields.items():
                    print("...The model found field '{}' to have label '{}'".format(
                        name, field.label
                    ))
        # [END training_async]
            # Training result information
            for doc in model.training_documents:
                print("Document name: {}".format(doc.document_name))
                print("Document status: {}".format(doc.status))
                print("Document page count: {}".format(doc.page_count))
                print("Document errors: {}".format(doc.errors))

async def main():
    sample = TrainUnlabeledModelSampleAsync()
    await sample.train_unlabeled_model()


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())