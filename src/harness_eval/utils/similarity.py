from __future__ import annotations

from typing import TYPE_CHECKING

# numpy, scipy and scikit-learn are imported inside the functions that use
# them: importing them here costs most of the CLI's startup time (#140).
if TYPE_CHECKING:
    import numpy as np
    from scipy.sparse import spmatrix
    from sklearn.feature_extraction.text import TfidfVectorizer


def tfidf_similarity(text_a: str, text_b: str) -> float:
    """Compute cosine similarity between two texts using TF-IDF vectors."""
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity

    if not text_a.strip() or not text_b.strip():
        return 0.0
    vectorizer = TfidfVectorizer()
    try:
        tfidf_matrix = vectorizer.fit_transform([text_a, text_b])
    except ValueError:
        return 0.0
    sim = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:2])
    return float(sim[0][0])


class SimilarityMatrix:
    """Pre-computed pairwise cosine-similarity matrix over a named corpus.

    Build once with :func:`build_similarity_matrix`, then look up any pair
    in O(1).
    """

    __slots__ = ("_names", "_index", "_matrix")

    def __init__(self, names: list[str], matrix: np.ndarray) -> None:
        self._names = names
        self._index: dict[str, int] = {name: i for i, name in enumerate(names)}
        self._matrix = matrix

    def get(self, a: str, b: str) -> float:
        """Return cosine similarity between texts *a* and *b* (by name)."""
        i = self._index.get(a)
        j = self._index.get(b)
        if i is None or j is None:
            return 0.0
        return float(self._matrix[i, j])

    def pairs_above(self, threshold: float) -> list[tuple[str, str, float]]:
        """Return ``(name_a, name_b, similarity)`` for unique pairs ≥ *threshold*.

        Only the upper triangle is returned (each unordered pair once).
        """
        import numpy as np

        n = len(self._names)
        if n < 2:
            return []
        rows, cols = np.where(self._matrix >= threshold)
        mask = rows < cols  # upper triangle only
        return [
            (self._names[int(r)], self._names[int(c)], float(self._matrix[r, c]))
            for r, c in zip(rows[mask], cols[mask], strict=False)
        ]


def build_similarity_matrix(texts: dict[str, str]) -> SimilarityMatrix:
    """Fit one TF-IDF vectorizer over *texts* and return the similarity matrix.

    Empty or whitespace-only values are silently dropped.
    """
    import numpy as np
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity

    names: list[str] = []
    docs: list[str] = []
    for name, text in texts.items():
        if text.strip():
            names.append(name)
            docs.append(text)

    if len(docs) < 2:
        return SimilarityMatrix(names, np.eye(max(len(names), 1)))

    vectorizer = TfidfVectorizer()
    try:
        tfidf = vectorizer.fit_transform(docs)
    except ValueError:
        return SimilarityMatrix(names, np.eye(len(names)))

    sim = cosine_similarity(tfidf)
    return SimilarityMatrix(names, sim)


class TfidfIndex:
    """Pre-fitted TF-IDF index for fast similarity queries against new texts.

    Build once with :func:`build_tfidf_index`, then call :meth:`query` to
    compare an arbitrary text against every indexed document in one sparse
    matrix–vector product.
    """

    __slots__ = ("_vectorizer", "_matrix", "_names")

    def __init__(
        self,
        vectorizer: TfidfVectorizer | None,
        matrix: spmatrix | None,
        names: list[str],
    ) -> None:
        self._vectorizer = vectorizer
        self._matrix = matrix
        self._names = names

    def query(self, text: str) -> dict[str, float]:
        """Return ``{name: similarity}`` for *text* against every indexed doc."""
        from sklearn.metrics.pairwise import cosine_similarity

        if self._vectorizer is None or not self._names or not text.strip():
            return {}
        try:
            vec = self._vectorizer.transform([text])
        except ValueError:
            return {}
        sims = cosine_similarity(vec, self._matrix)[0]
        return {name: float(sim) for name, sim in zip(self._names, sims, strict=False)}


def build_tfidf_index(texts: dict[str, str]) -> TfidfIndex:
    """Fit a TF-IDF vectorizer over *texts* for later :meth:`TfidfIndex.query` calls.

    Empty or whitespace-only values are silently dropped.
    """
    from sklearn.feature_extraction.text import TfidfVectorizer

    names: list[str] = []
    docs: list[str] = []
    for name, text in texts.items():
        if text.strip():
            names.append(name)
            docs.append(text)

    if not docs:
        return TfidfIndex(None, None, [])

    vectorizer = TfidfVectorizer()
    try:
        matrix = vectorizer.fit_transform(docs)
    except ValueError:
        return TfidfIndex(None, None, [])

    return TfidfIndex(vectorizer, matrix, names)
