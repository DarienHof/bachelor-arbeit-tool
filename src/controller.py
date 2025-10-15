import os
import random
from pathlib import Path

from dotenv import load_dotenv

from connector import get_connector
from injector import Injector
from src.comparer import Comparer
from src.sanitizer import Sanitizer
from src.utils.fileHelper import read_lines, write_lines, ensure_dir
from src.utils.models import AttackPayloads, InjectionRecord, SanitizeRecord, LLMAnswer
from src.utils.splitter import Splitter


def env_path(name: str) -> Path:
    v = os.getenv(name)
    if not v:
        raise RuntimeError(f"env {name} fehlt")
    return Path(v).resolve()


def env_int(name: str) -> int:
    v = os.getenv(name)
    if not v:
        raise RuntimeError(f"env {name} fehlt")
    return int(v)


def env_str_list(name: str) -> list[str]:
    v = os.getenv(name)
    if not v or v.strip() == "":
        return []
    return [s.strip() for s in v.split(",") if s.strip()]


load_dotenv()
model_names = env_str_list("MODEL_NAMES")
hardened_model_names = env_str_list("HARDENED_MODEL_NAMES")
seed = env_int("SEED")


def sanitize_file(injectedLines: list[str], injections: list[InjectionRecord], sanitizer: Sanitizer) -> list[
    SanitizeRecord]:
    if not injectedLines:
        raise ValueError(f"Injected Lines are empty")

    if not injections:
        raise ValueError(f"Injections are empty")

    maximum_file_sanitized = env_int("MAXIMUM_FILE_SANITIZED")

    result = sanitizer.file_sanitize(injectedLines, injections, env_path("CAMO_DIR").joinpath("camo_file.txt"), "start",
                                     maximum_file_sanitized)

    result.append(sanitizer.multi_sanitize(injectedLines, injections, env_path("CAMO_DIR").joinpath("camo_part_before.txt"),True))

    result.append(sanitizer.multi_sanitize(injectedLines, injections, env_path("CAMO_DIR").joinpath("camo_part_after.txt"),False))

    result.sort(key=lambda x: x.id)

    return result


def llm_log_analyse(filePath: Path) -> dict[str, tuple[list[LLMAnswer], float]]:
    answers: dict[str, tuple[list[LLMAnswer], float]] = {}
    for model_name in model_names:
        connector = get_connector(model_name)
        print(f"Connecting {model_name} to {filePath}")
        answers.update({f"{model_name}": connector.connect(filePath, False)})

    for model_name in hardened_model_names:
        connector = get_connector(model_name)
        print(f"Connecting {model_name} to {filePath}")
        answers.update({f"{model_name}_hardened": connector.connect(filePath, True)})

    return answers


def main(seed: int) -> None:
    rng = random.Random(seed)

    splitter_packet_count = env_int("SPLITTER_PACKET_COUNT")
    splitter_packet_site = env_int("SPLITTER_PACKET_SIZE")
    per_attack = env_int("PER_ATTACK")

    splitter = Splitter(splitter_packet_count, splitter_packet_site)
    injector = Injector(AttackPayloads(env_path("ATTACKS_DIR")))
    sanitizer = Sanitizer(seed=rng.randint(0, 1000000))
    comparer = Comparer()

    for filePath in env_path("INPUT_DIR").iterdir():
        if filePath.suffix != ".txt" and filePath.suffix != ".log":
            continue

        lines = read_lines(filePath)
        if not lines:
            raise ValueError(f"{filePath} is empty")

        print(f"Processing {filePath}")

        packages = splitter.split(lines)

        for i, package in enumerate(packages):
            injections, injectedLines = injector.inject(package, per_attack, seed=rng.randint(0, 1000000))

            ensure_dir(env_path("INJECTED_DIR"))
            write_path = env_path("INJECTED_DIR").joinpath(f"{filePath.stem}_injected_package{i}.log")
            write_lines(write_path, injectedLines)

            llmAnwersInjected = llm_log_analyse(write_path)

            print(f"Wrote {len(injections)} injections to {write_path}")

            results = sanitize_file(injectedLines, injections, sanitizer)

            write_path_sanitized = env_path("SANITIZED_DIR").joinpath(f"{write_path.stem}")
            ensure_dir(write_path_sanitized)
            for result in results:
                write_path = write_path_sanitized.joinpath(f"sanitized_{result.id}.log")
                write_lines(write_path, result.lines)

            llmAnswersListSanatized: list[dict[str, tuple[list[LLMAnswer], float]]] = []
            for sanitizPath in write_path_sanitized.iterdir():
                print(f"Analysing {sanitizPath}")
                llmAnswersListSanatized.append(llm_log_analyse(sanitizPath))

            write_path_output = env_path("OUTPUT_DIR").joinpath(f"{seed}").joinpath(f"{filePath.stem}_{i}")
            ensure_dir(write_path_output)
            comparer.compare(write_path_output, i, injections, llmAnwersInjected, results, llmAnswersListSanatized)

        write_path_output = env_path("OUTPUT_DIR").joinpath(f"{seed}")
        ensure_dir(write_path_output)
        comparer.completeTest(write_path_output, filePath.stem)
        print("")
        print(f"Finished {filePath}")
        print("")
        print("#"*50)

main(seed)
