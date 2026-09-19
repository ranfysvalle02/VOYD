"""Voyage AI embeddings.

The client is created lazily so importing/constructing VOYD never requires
network access or a valid key -- only actual embedding calls do. Text is
truncated to a bounded window before it leaves the process.
"""

from __future__ import annotations

from ..config import VoyageConfig


class VoyageIntelligence:
    def __init__(self, config: VoyageConfig):
        self.config = config
        self._client = None

    def _get_client(self):
        if self._client is None:
            import voyageai  # imported lazily; only needed when embedding

            self._client = voyageai.AsyncClient(api_key=self.config.api_key)
        return self._client

    def _truncate(self, text: str) -> str:
        return text[: self.config.max_input_chars]

    async def _embed(self, text: str, input_type: str) -> list[float]:
        """One call, two input types.

        The two public methods below differ by exactly one string, and that
        string is load-bearing: Voyage embeds documents and queries
        asymmetrically, so a query vector and a document vector are meant to
        be produced differently and compared to each other. What must *not*
        differ is everything else -- the model and the truncation window --
        and writing the call twice is how they come to. A query embedded with
        a different model than the corpus is the cosine inversion measured in
        ``engine/admission.py``: no error, no warning, and unrelated text
        outranking the document being looked for.
        """
        client = self._get_client()
        resp = await client.embed([self._truncate(text)],
                                  model=self.config.model,
                                  input_type=input_type)
        return list(resp.embeddings[0])

    async def embed_document(self, text: str) -> list[float]:
        return await self._embed(text, "document")

    async def embed_query(self, text: str) -> list[float]:
        return await self._embed(text, "query")
