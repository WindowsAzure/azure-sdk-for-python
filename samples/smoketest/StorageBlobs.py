from azure.storage.blob import BlobClient
import os

class StorageBlob:
    def __init__(self):
        connectionString = os.environ["STORAGE_CONNECTION_STRING"]
        self.blob = BlobClient.from_connection_string(connectionString, container="mycontainer", blob="pyTestBlob.txt")

    def uploadBLob(self):
        print("uploading blob...")
        self.data = "This is a sample data for Python Test"
        self.blob.upload_blob(self.data)
        print("\tdone")

    def downloadBlob(self):
        print("downloading blob...")
        with open("./downloadedBlob.txt", "wb+") as my_blob:
            my_blob.writelines(self.blob.download_blob())

        print("\tdone")

    def deleteBlob(self):
        print("Cleaning up the resource...")
        self.blob.delete_blob()
        print("\tdone")

    def Run(self):
        print()
        print("------------------------")
        print("Storage - Blob")
        print("------------------------")
        print("1) Upload a Blob")
        print("2) Download a Blob")
        print("3) Delete that Blob (Clean up the resource)")
        print()
        
        #Ensure that the blob does not exists before the tests
        try:
            self.deleteBlob()
        except:
            pass
        
        try:
            self.uploadBLob()
            self.downloadBlob()
        finally:
            self.deleteBlob()