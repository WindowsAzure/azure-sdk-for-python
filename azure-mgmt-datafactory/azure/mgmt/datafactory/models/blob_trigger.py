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

from .multiple_pipeline_trigger import MultiplePipelineTrigger


class BlobTrigger(MultiplePipelineTrigger):
    """Trigger that runs everytime the selected Blob container changes.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param description: Trigger description.
    :type description: str
    :ivar runtime_state: Indicates if trigger is running or not. Updated when
     Start/Stop APIs are called on the Trigger. Possible values include:
     'Started', 'Stopped', 'Disabled'
    :vartype runtime_state: str or
     ~azure.mgmt.datafactory.models.TriggerRuntimeState
    :param type: Constant filled by server.
    :type type: str
    :param pipelines: Pipelines that need to be started.
    :type pipelines:
     list[~azure.mgmt.datafactory.models.TriggerPipelineReference]
    :param folder_path: The path of the container/folder that will trigger the
     pipeline.
    :type folder_path: str
    :param max_concurrency: The max number of parallel files to handle when it
     is triggered.
    :type max_concurrency: int
    :param linked_service: The Azure Storage linked service reference.
    :type linked_service:
     ~azure.mgmt.datafactory.models.LinkedServiceReference
    """

    _validation = {
        'runtime_state': {'readonly': True},
        'type': {'required': True},
    }

    _attribute_map = {
        'description': {'key': 'description', 'type': 'str'},
        'runtime_state': {'key': 'runtimeState', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'pipelines': {'key': 'pipelines', 'type': '[TriggerPipelineReference]'},
        'folder_path': {'key': 'typeProperties.folderPath', 'type': 'str'},
        'max_concurrency': {'key': 'typeProperties.maxConcurrency', 'type': 'int'},
        'linked_service': {'key': 'typeProperties.linkedService', 'type': 'LinkedServiceReference'},
    }

    def __init__(self, description=None, pipelines=None, folder_path=None, max_concurrency=None, linked_service=None):
        super(BlobTrigger, self).__init__(description=description, pipelines=pipelines)
        self.folder_path = folder_path
        self.max_concurrency = max_concurrency
        self.linked_service = linked_service
        self.type = 'BlobTrigger'
