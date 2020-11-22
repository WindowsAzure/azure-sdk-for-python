
import os

from ._test_base_legacy import _LegacyShareTest


class LegacyDownloadTest(_LegacyShareTest):
    file_name = "downloadtest"

    async def GlobalSetupAsync(self):
        await super().GlobalSetupAsync()
        data = b'a' * self.Arguments.size
        self.service_client.create_file_from_bytes(
            share_name=self.share_name,
            directory_name=None,
            file_name=self.file_name,
            file=data)

    def Run(self):
        self.service_client.get_file_to_bytes(
            share_name=self.share_name,
            directory_name=None,
            file_name=self.file_name,
            max_connections=self.Arguments.parallel)

    async def RunAsync(self):
        raise NotImplementedError("Async not supported for legacy tests.")

    @staticmethod
    def AddArguments(parser):
        super(LegacyDownloadTest, LegacyDownloadTest).AddArguments(parser)
        parser.add_argument('-s', '--size', nargs='?', type=int, help='Size of files to download.  Default is 10240.', default=10240)
