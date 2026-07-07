from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass
class JavaBodyBuilder:

    indent: str = "    "
    _level: int = 0
    _lines: List[str] = field(default_factory=list)

    def line(self, statement: str) -> None:
        self._lines.append(f"{self.indent * self._level}{statement}")

    def open(self, header: str) -> None:
        self.line(f"{header} {{")
        self._level += 1

    def transition(self, header: str) -> None:
        if self._level <= 0:
            raise ValueError("cannot transition outside a Java block")
        self._level -= 1
        self.line(f"}} {header} {{")
        self._level += 1

    def close(self) -> None:
        if self._level <= 0:
            raise ValueError("cannot close an unopened Java block")
        self._level -= 1
        self.line("}")

    def build(self) -> List[str]:
        if self._level:
            raise ValueError("cannot render an unclosed Java block")
        return list(self._lines)
