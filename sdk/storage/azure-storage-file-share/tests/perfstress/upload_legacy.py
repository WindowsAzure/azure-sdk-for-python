import os
import uuid

from ._test_base_legacy import _LegacyShareTest

from azure_devtools.perfstress_tests import RandomStream
from azure_devtools.perfstress_tests import AsyncRandomStream


class LegacyUploadTest(_LegacyShareTest):
    def __init__(self, arguments):
        super().__init__(arguments)
        self.file_name = "sharefiletest-" + str(uuid.uuid4())
        self.data = b'a' * self.Arguments.size

    def Run(self):
        if self.Arguments.stream:
            data = RandomStream(self.Arguments.size)
            self.service_client.create_file_from_stream(
                share_name=self.share_name,
                directory_name=None,
                file_name=self.file_name,
                stream=data)
        else:
            self.service_client.create_file_from_bytes(
                share_name=self.share_name,
                directory_name=None,
                file_name=self.file_name,
                file=self.data)

    async def RunAsync(self):
        raise NotImplementedError("Async not supported for legacy tests.")

    @staticmethod
    def AddArguments(parser):
        super(LegacyUploadTest, LegacyUploadTest).AddArguments(parser)
        parser.add_argument('-s', '--size', nargs='?', type=int, help='Size of blobs to upload.  Default is 10240.', default=10240)
        parser.add_argument('--stream', action='store_true', help='Upload stream instead of byte array.', default=False)
