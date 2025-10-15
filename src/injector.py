import random

from src.utils.logRowHelper import build_log_line_with_payload
from src.utils.models import AttackPayloads, InjectionRecord, AttackType


class Injector:
    def __init__(self, attacks: AttackPayloads):
        self.attacks = attacks

    def inject(self,
               lines: list[str],
               per_Attack: int,
               seed: int = random.randint(0, 1000000)) -> tuple[list[InjectionRecord], list[str]]:
        if not lines:
            raise ValueError(f"Input Lines are empty")

        if per_Attack * len(self.attacks.payloads) > len(lines):
            raise ValueError(f"Not enough lines for {len(self.attacks.payloads)} attacks")

        rng = random.Random(seed)
        candidate_positions = list(range(len(lines)))
        rng.shuffle(candidate_positions)

        insertions: list[tuple[int, str, AttackType, int]] = []
        for attackType, payload_list in self.attacks.payloads.items():
            for i in range(per_Attack):
                payload = rng.choice(payload_list)
                position = candidate_positions.pop()
                if attackType == "DoS/DDoS":
                    insertions.append((position, payload, attackType, rng.randint(1, 5)))
                else:
                    insertions.append((position, payload, attackType, 1))

        insertions.sort(key=lambda x: x[0])
        offset = 0
        records: list[InjectionRecord] = []
        for lineID, attackPayload, attackType, count in insertions:
            position = lineID + offset
            for i in range(count):
                lines.insert(position, str(build_log_line_with_payload(attackPayload,
                                                                       seed=rng.randint(0, 1000000),
                                                                       line_before=lines[position - 1] if position > 0 else None,
                                                                       line_after=lines[position] if position < len(lines) else None)))
                offset += 1
            records.append(InjectionRecord(position + 1, attackType, attackPayload))

        return records, lines
