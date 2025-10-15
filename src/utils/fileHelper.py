from pathlib import Path

def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def read_lines(p: Path) -> list[str]:
    with p.open(encoding="utf-8") as f:
        return [ln.rstrip("\n") for ln in f]

def write_lines(p: Path, lines: list[str]) -> None:
    with p.open("w", encoding="utf-8") as f:
        for ln in lines:
            f.write(ln + "\n")
