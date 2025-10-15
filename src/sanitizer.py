import random
from pathlib import Path
from typing import Literal

from src.utils.logRowHelper import build_log_line_with_payload
from src.utils.fileHelper import read_lines, ensure_dir, write_lines
from src.utils.models import InjectionRecord, CamouflageRecord, SanitizeRecord

InsertMode = Literal["start", "end", "random"]


class Sanitizer:
    def __init__(self, seed: int = random.randint(0, 1000000)):
        self.rng = random.Random(seed)

    def file_sanitize(self,
                      lines: list[str],
                      injections: list[InjectionRecord],
                      camoFilePath: Path,
                      mode: InsertMode,
                      maximumCount: int = -1) -> list[SanitizeRecord]:
        camoLines = read_lines(camoFilePath)
        if not camoLines:
            raise ValueError(f"{camoFilePath} is empty")

        if not lines:
            raise ValueError(f"Input Lines are empty")

        result: list[SanitizeRecord] = []

        self.rng.shuffle(camoLines)

        for i, camo in enumerate(camoLines, start=1):
            if i > maximumCount != -1: break
            if mode == "start":
                insert_index = 0
            elif mode == "end":
                insert_index = len(lines)
            elif mode == "random":
                insert_index = self.rng.randint(0, len(lines))
            else:
                raise ValueError(f"Invalid mode: {mode}")

            copy_lines = lines[:]
            logLine = build_log_line_with_payload(camo,
                                                  seed=self.rng.randint(0, 1000000),
                                                  line_before=lines[insert_index - 1] if insert_index > 0 else None,
                                                  line_after=lines[insert_index] if insert_index < len(lines) else None)
            copy_lines.insert(insert_index, str(logLine))

            updated: list[InjectionRecord] = []
            for record in injections:
                new_line_no = record.line_no
                if (record.line_no - 1) >= insert_index:
                    new_line_no += 1
                updated.append(InjectionRecord(new_line_no, record.attack_type, record.payload, record.count))

            result.append(SanitizeRecord(id = i + 1,injectionRecords = updated, camouflageRecords = [CamouflageRecord(insert_index + 1, camo)], lines = copy_lines))


        return result


    def multi_sanitize(self,
                       lines: list[str],
                       injections: list[InjectionRecord],
                       camoFilePath: Path,
                       before: bool = True) -> SanitizeRecord:
        if not lines:
            raise ValueError(f"Lines for multi_sanitize are empty")

        camoLines = read_lines(camoFilePath)
        if not camoLines:
            raise ValueError(f"{camoFilePath} is empty")

        lines = lines[:]

        injectionsList: list[InjectionRecord] = []
        camoList: list[CamouflageRecord] = []

        camo_added = 0
        injections.sort(key=lambda x: x.line_no)
        last_camo_line = 0

        for injection in injections:
            spaces = self.rng.randint(0, 5)
            current_injection_line = injection.line_no + camo_added

            if before:
                insert_index = current_injection_line - 1 - spaces
                if insert_index < 0:
                    insert_index = 0

                new_injection_line = current_injection_line + 1
            else:
                insert_index = current_injection_line + spaces
                if insert_index > len(lines):
                    insert_index = len(lines)
                if last_camo_line > current_injection_line:
                    new_injection_line = current_injection_line - 1
                else:
                    new_injection_line = current_injection_line

                last_camo_line = insert_index

            payload = self.rng.choice(camoLines)
            logLine = build_log_line_with_payload(payload,
                                                  seed=self.rng.randint(0, 1000000),
                                                  line_before=lines[insert_index - 1] if insert_index > 0 else None,
                                                  line_after=lines[insert_index] if insert_index < len(lines) else None)
            lines.insert(insert_index, str(logLine))



            updated_injectionsList: list[InjectionRecord] = []
            if before:
                for existing_injection in injectionsList:
                    if existing_injection.line_no > insert_index:
                        updated_injectionsList.append(InjectionRecord(
                            existing_injection.line_no + 1,
                            existing_injection.attack_type,
                            existing_injection.payload,
                            existing_injection.count
                        ))
                    else:
                        updated_injectionsList.append(existing_injection)

                injectionsList = updated_injectionsList

            updated_camoList: list[CamouflageRecord] = []
            for existing_camo in camoList:
                if existing_camo.line_no > insert_index:
                    updated_camoList.append(CamouflageRecord(
                        existing_camo.line_no + 1,
                        existing_camo.camouflage,
                        existing_camo.spacing
                    ))
                else:
                    updated_camoList.append(existing_camo)

            camoList = updated_camoList

            injectionsList.append(InjectionRecord(
                new_injection_line,
                injection.attack_type,
                injection.payload,
                injection.count
            ))

            camoList.append(CamouflageRecord(insert_index + 1, payload, spacing=spaces))

            camo_added += 1

        return SanitizeRecord(id=0 if before else 1, lines=lines, injectionRecords=injectionsList, camouflageRecords=camoList)