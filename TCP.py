from datetime import datetime
from calendar import monthrange
from collections import deque
from dataclasses import dataclass
from typing import List, Tuple, Optional
import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

SSZ = 16
NNSZ = 16
KSZE = 32


@dataclass
class Cell:
    y: int
    m: int
    d: int

    def to_b(self) -> bytes:
        return f"{self.y:04d}-{self.m:02d}-{self.d:02d}".encode()

    def __hash__(self):
        return hash((self.y, self.m, self.d))

    def __eq__(self, o):
        return (self.y, self.m, self.d) == (o.y, o.m, o.d)


@dataclass
class Move:
    t: str  # h /v
    v: int  # neg / pos


class Findway:
    def __init__(self, rule: str = "shortest"):
        self.rule = rule

    def _dim(self, y: int, m: int) -> int:
        return monthrange(y, m)[1]

    def _nb(self, c: Cell) -> List[Tuple[Cell, Move]]:
        nb = []
        y, m, d = c.y, c.m, c.d

        for dm in (-1, 1):
            nm = m + dm
            ny = y
            if nm < 1:
                nm = 12
                ny -= 1
            elif nm > 12:
                nm = 1
                ny += 1
            nd = min(d, self._dim(ny, nm))
            nb.append((Cell(ny, nm, nd), Move("h", dm)))

        for dy in (-1, 1):
            ny = y + dy
            nm = m
            md = self._dim(ny, nm)
            nd = md + 1 - d
            if nd < 1:
                nd = 1
            if nd > md:
                nd = md
            nb.append((Cell(ny, nm, nd), Move("v", dy)))

        return nb

    def _short(self, a: Cell, b: Cell) -> List[Move]:
        if a == b:
            return []
        q = deque([(a, [])])
        v = {a}
        while q:
            c, p = q.popleft()
            for n, mv in self._nb(c):
                if n == b:
                    return p + [mv]
                if n not in v:
                    v.add(n)
                    q.append((n, p + [mv]))
        raise ValueError("No path")

    def path(self, a: Cell, b: Cell) -> List[Move]:
        return self._short(a, b)


class Transcript:
    @staticmethod
    def gen(a: Cell, p: List[Move]) -> bytes:
        t = [a.to_b()]
        c = a
        for mv in p:
            t.append(f"|{mv.t}:{mv.v}|".encode())
            y, m, d = c.y, c.m, c.d
            if mv.t == "h":
                m += mv.v
                if m < 1:
                    m = 12
                    y -= 1
                elif m > 12:
                    m = 1
                    y += 1
                d = min(d, monthrange(y, m)[1])
            else:
                y += mv.v
                md = monthrange(y, m)[1]
                d = md + 1 - d
                if d < 1:
                    d = 1
                if d > md:
                    d = md
            c = Cell(y, m, d)
            t.append(c.to_b())
        return b"".join(t)

    @staticmethod
    def cells(a: Cell, p: List[Move]) -> List[Cell]:
        lst = [a]
        c = a
        for mv in p:
            y, m, d = c.y, c.m, c.d
            if mv.t == "h":
                m += mv.v
                if m < 1:
                    m = 12
                    y -= 1
                elif m > 12:
                    m = 1
                    y += 1
                d = min(d, monthrange(y, m)[1])
            else:
                y += mv.v
                md = monthrange(y, m)[1]
                d = md + 1 - d
                if d < 1:
                    d = 1
                if d > md:
                    d = md
            c = Cell(y, m, d)
            lst.append(c)
        return lst


class Derive:
    def __init__(self, slt: Optional[bytes] = None):
        self.slt = slt or os.urandom(SSZ)

    def key(self, tr: bytes, info: bytes = b"tpc") -> bytes:
        sd = hashlib.sha256(self.slt + tr).digest()
        hkdf = HKDF(algorithm=hashes.SHA256(), length=KSZE, salt=self.slt, info=info)
        return hkdf.derive(sd + self.slt)


class TPC:
    def __init__(self, rule: str = "shortest"):
        self.rule = rule
        self.pf = Findway(rule)

    def enc(
        self,
        txt: str,
        a: Tuple[int, int, int],
        b: Tuple[int, int, int],
        slt: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes, bytes, List[Move], List[Cell]]:
        sy, sm, sd = a
        ey, em, ed = b
        start = Cell(sy, sm, sd)
        end = Cell(ey, em, ed)
        p = self.pf.path(start, end)
        cells = Transcript.cells(start, p)
        tr = Transcript.gen(start, p)
        d = Derive(slt)
        key = d.key(tr)
        nonce = os.urandom(NNSZ)
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
        enc = cipher.encryptor()
        ct = enc.update(txt.encode()) + enc.finalize()
        return ct, nonce, d.slt, p, cells

    def dec(
        self,
        ct: bytes,
        nonce: bytes,
        slt: bytes,
        a: Tuple[int, int, int],
        b: Tuple[int, int, int],
    ) -> Tuple[str, List[Move], List[Cell]]:
        sy, sm, sd = a
        ey, em, ed = b
        start = Cell(sy, sm, sd)
        end = Cell(ey, em, ed)
        p = self.pf.path(start, end)
        cells = Transcript.cells(start, p)
        tr = Transcript.gen(start, p)
        d = Derive(slt)
        key = d.key(tr)
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
        dec = cipher.decryptor()
        pt = dec.update(ct) + dec.finalize()
        return pt.decode(), p, cells

    def enc_pack(
        self, txt: str, a: Tuple[int, int, int], b: Tuple[int, int, int]
    ) -> Tuple[bytes, List[Move], List[Cell]]:
        ct, nonce, slt, p, cells = self.enc(txt, a, b)
        return slt + nonce + ct, p, cells

    def dec_pack(
        self, data: bytes, a: Tuple[int, int, int], b: Tuple[int, int, int]
    ) -> Tuple[str, List[Move], List[Cell]]:
        slt = data[:SSZ]
        nonce = data[SSZ : SSZ + NNSZ]
        ct = data[SSZ + NNSZ :]
        return self.dec(ct, nonce, slt, a, b)
