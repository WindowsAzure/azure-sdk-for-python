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


class BootDiagnosticsInstanceView(Model):
    """The instance view of a virtual machine boot diagnostics.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar console_screenshot_blob_uri: The console screenshot blob URI.
    :vartype console_screenshot_blob_uri: str
    :ivar serial_console_log_blob_uri: The Linux serial console log blob Uri.
    :vartype serial_console_log_blob_uri: str
    :ivar status: The boot diagnostics status information for the VM. <br><br>
     NOTE: It will be set only if there are errors encountered in enabling boot
     diagnostics.
    :vartype status: ~azure.mgmt.compute.v2019_03_01.models.InstanceViewStatus
    """

    _validation = {
        'console_screenshot_blob_uri': {'readonly': True},
        'serial_console_log_blob_uri': {'readonly': True},
        'status': {'readonly': True},
    }

    _attribute_map = {
        'console_screenshot_blob_uri': {'key': 'consoleScreenshotBlobUri', 'type': 'str'},
        'serial_console_log_blob_uri': {'key': 'serialConsoleLogBlobUri', 'type': 'str'},
        'status': {'key': 'status', 'type': 'InstanceViewStatus'},
    }

    def __init__(self, **kwargs) -> None:
        super(BootDiagnosticsInstanceView, self).__init__(**kwargs)
        self.console_screenshot_blob_uri = None
        self.serial_console_log_blob_uri = None
        self.status = None
