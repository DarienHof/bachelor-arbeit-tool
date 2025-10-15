from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from src.utils.fileHelper import read_lines

AttackType = Literal["SQLi", "XSS", "CmdInject", "DoS/DDoS", "UNKNOWN", "Sanitize"]

@dataclass(frozen=True)
class SanitizeRecord:
    id: int
    lines: list[str]
    injectionRecords: list[InjectionRecord]
    camouflageRecords: list[CamouflageRecord]


@dataclass(frozen=True)
class InjectionRecord:
    line_no: int
    attack_type: AttackType
    payload: str
    count: int = 1

    def __str__(self) -> str:
        return f"{self.line_no}: {self.attack_type} mit payload: {self.payload}"


@dataclass(frozen=True)
class CamouflageRecord:
    line_no: int
    camouflage: str
    spacing: int = 0


@dataclass(frozen=True)
class FileJobResult:
    source_file: Path
    infected_file: Path
    sanitized_file: Path
    injections: tuple[InjectionRecord, ...]
    camouflages: tuple[CamouflageRecord, ...]

@dataclass(frozen=True)
class LLMAnswer:
    id: int
    attackType: AttackType
    confidence: float
    evidence: str
    line_no: int

    def __str__(self) -> str:
        return f"{self.id}: {self.attackType} in Line {self.line_no} mit confidence: {self.confidence} erkannt. Matches: {self.matches} und Evidence: {self.evidence}"


@dataclass
class ComparisonResult:
    true_positives: int
    false_negatives: int
    false_positives: int
    time_needed: float = 0.0

    def __str__(self) -> str:
        return f"TP: {self.true_positives}, FN: {self.false_negatives}, FP: {self.false_positives}, Precision: {self.precision()}, Recall: {self.recall()}, F1-Score: {self.f1_score()}, Zeit: {self.time_needed}"

    def to_dict(self) -> dict:
        return {
            "true_positives": self.true_positives,
            "false_negatives": self.false_negatives,
            "false_positives": self.false_positives,
            "precision": self.precision(),
            "recall": self.recall(),
            "f1_score": self.f1_score(),
            "time_needed": self.time_needed,
        }

    def precision(self) -> float:
        if self.true_positives + self.false_positives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_positives)

    def recall(self) -> float:
        if self.true_positives + self.false_negatives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_negatives)

    def f1_score(self) -> float:
        p = self.precision()
        r = self.recall()
        if p + r == 0:
            return 0.0
        return 2 * (p * r) / (p + r)


class AttackPayloads:
    def __init__(self, attacks_dir: Path):
        def load(name: str) -> list[str]:
            path = attacks_dir / name
            print(f"Loading {path}")
            return read_lines(path)

        self.payloads: dict[AttackType, list[str]] = {
            "SQLi": load("sql_injection.txt"),
            "XSS": load("xss.txt"),
            "CmdInject": load("command_injection.txt"),
            "DoS/DDoS": load("dos_ddos.txt"),
        }


@dataclass()
class LogRow:
    line_no: int | None
    ip: str
    time: str
    method: str
    path: str
    protocol: str
    status: str
    size: str
    referer: str
    ua: str

    def __str__(self) -> str:
        return f"{self.ip} - - [{self.time}] \"{self.method} {self.path} {self.protocol}\" {self.status} {self.size} \"{self.referer}\" \"{self.ua}\""
