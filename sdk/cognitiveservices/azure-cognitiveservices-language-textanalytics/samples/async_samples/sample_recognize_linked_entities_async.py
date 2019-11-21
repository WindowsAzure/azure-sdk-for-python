# coding: utf-8

# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------

"""
FILE: sample_recognize_linked_entities_async.py

DESCRIPTION:
    This sample demonstrates how to detect linked entities in a batch of documents.
    Each entity found in the document will have a link associated with it from a
    data source.

USAGE:
    python sample_recognize_linked_entities_async.py

    Set the environment variables with your own values before running the sample:
    1) AZURE_TEXT_ANALYTICS_ENDPOINT - the endpoint to your cognitive services resource.
    2) AZURE_COGNITIVE_SERVICES_KEY - your cognitive services account key

OUTPUT:
    Document text: Microsoft moved its headquarters to Bellevue, Washington in January 1979.

    Entity: Bellevue, Washington
    Url: https://en.wikipedia.org/wiki/Bellevue,_Washington
    Data Source: Wikipedia
    Score: 0.6983422583846437
    Offset: 36
    Length: 20

    Entity: Microsoft
    Url: https://en.wikipedia.org/wiki/Microsoft
    Data Source: Wikipedia
    Score: 0.15940757036774889
    Offset: 0
    Length: 9

    Entity: January
    Url: https://en.wikipedia.org/wiki/January
    Data Source: Wikipedia
    Score: 0.006847036169509657
    Offset: 60
    Length: 7

    ------------------------------------------
    Document text: Steve Ballmer stepped down as CEO of Microsoft and was succeeded by Satya Nadella.

    Entity: Steve Ballmer
    Url: https://en.wikipedia.org/wiki/Steve_Ballmer
    Data Source: Wikipedia
    Score: 0.6718822567632026
    Offset: 0
    Length: 13

    Entity: Satya Nadella
    Url: https://en.wikipedia.org/wiki/Satya_Nadella
    Data Source: Wikipedia
    Score: 0.6813953196521605
    Offset: 68
    Length: 13

    Entity: Microsoft
    Url: https://en.wikipedia.org/wiki/Microsoft
    Data Source: Wikipedia
    Score: 0.16407777316549788
    Offset: 37
    Length: 9

    Entity: Chief executive officer
    Url: https://en.wikipedia.org/wiki/Chief_executive_officer
    Data Source: Wikipedia
    Score: 0.07353413770716566
    Offset: 30
    Length: 3

    ------------------------------------------
    Document text: Microsoft superó a Apple Inc. como la compañía más valiosa que cotiza en bolsa en el mundo.

    Entity: Apple Inc.
    Url: https://en.wikipedia.org/wiki/Apple_Inc.
    Data Source: Wikipedia
    Score: 0.6772289264768614
    Offset: 19
    Length: 10

    Entity: Microsoft
    Url: https://en.wikipedia.org/wiki/Microsoft
    Data Source: Wikipedia
    Score: 0.13153454442693202
    Offset: 0
    Length: 9

    ------------------------------------------

"""

import os
import asyncio


class RecognizeLinkedEntitiesSampleAsync(object):

    endpoint = os.getenv("AZURE_TEXT_ANALYTICS_ENDPOINT")
    key = os.getenv("AZURE_COGNITIVE_SERVICES_KEY")

    async def recognize_linked_entities_async(self):
        from azure.cognitiveservices.language.textanalytics.aio import TextAnalyticsClient
        text_analytics_client = TextAnalyticsClient(endpoint=self.endpoint, credential=self.key)
        documents = [
            "Microsoft moved its headquarters to Bellevue, Washington in January 1979.",
            "Steve Ballmer stepped down as CEO of Microsoft and was succeeded by Satya Nadella.",
            "Microsoft superó a Apple Inc. como la compañía más valiosa que cotiza en bolsa en el mundo.",
        ]

        async with text_analytics_client:
            result = await text_analytics_client.recognize_linked_entities(documents)

        docs = [doc for doc in result if not doc.is_error]

        for idx, doc in enumerate(docs):
            print("Document text: {}\n".format(documents[idx]))
            for entity in doc.entities:
                print("Entity: {}".format(entity.name))
                print("Url: {}".format(entity.url))
                print("Data Source: {}".format(entity.data_source))
                for match in entity.matches:
                    print("Score: {}".format(match.score))
                    print("Offset: {}".format(match.offset))
                    print("Length: {}\n".format(match.length))
            print("------------------------------------------")

    async def advanced_scenario_recognize_linked_entities_async(self):
        """This sample demonstrates how to retrieve batch statistics, the
        model version used, and the raw response returned from the service.

        It additionally shows an alternative way to pass in the input documents
        using a list[MultiLanguageInput] and supplying your own IDs and language hints along
        with the text.
        """
        from azure.cognitiveservices.language.textanalytics.aio import TextAnalyticsClient
        text_analytics_client = TextAnalyticsClient(endpoint=self.endpoint, credential=self.key)

        documents = [
            {"id": "0", "language": "en", "text": "Microsoft moved its headquarters to Bellevue, Washington in January 1979."},
            {"id": "1", "language": "en", "text": "Steve Ballmer stepped down as CEO of Microsoft and was succeeded by Satya Nadella."},
            {"id": "2", "language": "es", "text": "Microsoft superó a Apple Inc. como la compañía más valiosa que cotiza en bolsa en el mundo."},
        ]

        extras = []

        def callback(resp):
            extras.append(resp.statistics)
            extras.append(resp.model_version)
            extras.append(resp.raw_response)

        async with text_analytics_client:
            result = await text_analytics_client.recognize_linked_entities(
                documents,
                show_stats=True,
                model_version="latest",
                response_hook=callback
            )


async def main():
    sample = RecognizeLinkedEntitiesSampleAsync()
    await sample.recognize_linked_entities_async()
    await sample.advanced_scenario_recognize_linked_entities_async()

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
