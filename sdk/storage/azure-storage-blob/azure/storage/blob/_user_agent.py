# coding=utf-8
# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------

import platform
from ._version import VERSION

USER_AGENT = "azsdk-python-storage-blob/{} Python/{} ({})".format(
    VERSION, platform.python_version(), platform.platform()
)
