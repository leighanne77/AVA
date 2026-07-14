"""Merkle commitments over object hashes — provenance without exposure.

An `attest` answer commits to a set of objects by returning one Merkle root.
Later, the owner can prove any single object was in that attested set with a
short proof; the verifier needs only the root, the object's plaintext hash,
and this hashing scheme — no vault access, no secrets, fully offline.

Scheme notes:
  - leaves are the objects' sha256_plain values, sorted (canonical order —
    the same set always yields the same root);
  - domain separation (0x00 leaf / 0x01 node prefixes) prevents
    second-preimage games between leaves and internal nodes;
  - an odd node is promoted unchanged, never duplicated.
"""
import hashlib
from typing import Dict, List, Optional, Tuple

_LEAF = b"\x00"
_NODE = b"\x01"


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _leaf(hex_hash: str) -> bytes:
    return _h(_LEAF + bytes.fromhex(hex_hash))


def merkle_root_hex(hex_hashes: List[str]) -> Optional[str]:
    """Root over a set of hex hashes (order-independent: input is sorted)."""
    if not hex_hashes:
        return None
    level = [_leaf(x) for x in sorted(hex_hashes)]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(_h(_NODE + level[i] + level[i + 1]))
            else:
                nxt.append(level[i])          # odd node promoted unchanged
        level = nxt
    return level[0].hex()


def merkle_proof(hex_hashes: List[str], target_hex: str) -> List[Dict]:
    """Inclusion proof for target_hex: [{'sibling': hex, 'side': 'L'|'R'}, ...]."""
    ordered = sorted(hex_hashes)
    if target_hex not in ordered:
        raise ValueError("target hash is not in the set")
    idx = ordered.index(target_hex)
    level = [_leaf(x) for x in ordered]
    proof = []
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(_h(_NODE + level[i] + level[i + 1]))
                if i == idx or i + 1 == idx:
                    if i == idx:
                        proof.append({"sibling": level[i + 1].hex(), "side": "R"})
                    else:
                        proof.append({"sibling": level[i].hex(), "side": "L"})
                    idx = len(nxt) - 1
            else:
                nxt.append(level[i])
                if i == idx:
                    idx = len(nxt) - 1        # promoted: no sibling this level
        level = nxt
    return proof


def verify_membership(target_hex: str, proof: List[Dict], root_hex: str) -> bool:
    """Offline check that target_hex is committed to by root_hex."""
    node = _leaf(target_hex)
    for step in proof:
        sib = bytes.fromhex(step["sibling"])
        if step["side"] == "R":
            node = _h(_NODE + node + sib)
        elif step["side"] == "L":
            node = _h(_NODE + sib + node)
        else:
            return False
    return node.hex() == root_hex
