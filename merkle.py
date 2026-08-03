import hashlib
import json
from typing import Any

# Canonical zero root — returned instead of "" for an empty tree (FLAW-014)
ZERO_ROOT = "0" * 64


class MerkleTree:
    """
    Incremental Merkle Tree.

    FIX (FLAW-004): `add_leaf` now runs in O(1) amortised time.
    The tree is only rebuilt (O(N)) on demand when `get_root()` or
    `get_proof()` is called, and is cached until the next leaf is added.
    """

    def __init__(self):
        self.leaves: list[str] = []
        self._tree_cache: list[list[str]] | None = None   # None == dirty

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def add_leaf(self, data: dict[str, Any]) -> str:
        data_str = json.dumps(data, sort_keys=True, separators=(",", ":"))
        leaf_hash = hashlib.sha256(data_str.encode("utf-8")).hexdigest()
        self.leaves.append(leaf_hash)
        self._tree_cache = None   # invalidate cache
        return leaf_hash

    # ------------------------------------------------------------------
    # Internal: lazy build
    # ------------------------------------------------------------------

    def _build_tree(self) -> list[list[str]]:
        """Builds the full tree from leaves. Called lazily."""
        if not self.leaves:
            return []
        current_level: list[str] = list(self.leaves)
        tree: list[list[str]] = [current_level]
        while len(current_level) > 1:
            next_level: list[str] = []
            for i in range(0, len(current_level), 2):
                left  = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                combined = left + right
                next_level.append(hashlib.sha256(combined.encode("utf-8")).hexdigest())
            current_level = next_level
            tree.append(current_level)
        return tree

    @property
    def _tree(self) -> list[list[str]]:
        if self._tree_cache is None:
            self._tree_cache = self._build_tree()
        return self._tree_cache

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get_root(self) -> str:
        if not self._tree:
            return ZERO_ROOT            # FIX FLAW-014: never return ""
        return self._tree[-1][0]

    def get_proof(self, index: int) -> list[dict[str, str]]:
        proof: list[dict[str, str]] = []
        tree = self._tree
        if not tree or index >= len(self.leaves):
            return proof
        current_index = index
        for level in tree[:-1]:
            is_right_node = current_index % 2 == 1
            sibling_index = current_index - 1 if is_right_node else current_index + 1
            if sibling_index < len(level):
                sibling_hash = level[sibling_index]
                proof.append({
                    "position": "left" if is_right_node else "right",
                    "hash": sibling_hash,
                })
            else:
                proof.append({
                    "position": "right",
                    "hash": level[current_index],
                })
            current_index //= 2
        return proof


def verify_merkle_proof(leaf_hash: str, proof: list[dict[str, str]], root: str) -> bool:
    current_hash = leaf_hash
    for p in proof:
        if p["position"] == "left":
            combined = p["hash"] + current_hash
        else:
            combined = current_hash + p["hash"]
        current_hash = hashlib.sha256(combined.encode("utf-8")).hexdigest()
    return current_hash == root


def recompute_root_from_leaves(leaves: list[str]) -> str:
    """Mathematically rebuild the Merkle Root from raw leaf hashes."""
    if not leaves:
        return ZERO_ROOT              # FIX FLAW-014
    current_level: list[str] = list(leaves)
    while len(current_level) > 1:
        next_level: list[str] = []
        for i in range(0, len(current_level), 2):
            left  = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            combined = left + right
            next_level.append(hashlib.sha256(combined.encode("utf-8")).hexdigest())
        current_level = next_level
    return current_level[0]
