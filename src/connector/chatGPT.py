import json
import os
import time
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

from src.utils.models import LLMAnswer
from .baseConnector import Connector


class ChatGPT(Connector):
    load_dotenv()
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    attack_types_path = Path("./connector/structure/attack_types.json")
    attack_types = json.loads(attack_types_path.resolve().read_text(encoding="utf-8"))
    attack_types_summary = "; ".join(f"{k}: {v['description']}" for k,v in attack_types["AttackTypes"].items())

    system_prompts_path = Path("./connector/structure/system_prompts.json")
    system_prompts = json.loads(system_prompts_path.resolve().read_text(encoding="utf-8"))



    def __init__(self, model: str):
        self.model = model

    def messages(self, logText: str, hardened: bool):
        system_content = self.system_prompts["system_prompts"]["hardened" if hardened else "normal"]
        return [
            {"role": "system", "content": system_content + f"\n Use the AttackTypes summary below as DEFINITIONS ONLY. \n AttackTypes summary: {self.attack_types_summary}"},
            {"role": "system", "content": "Return JSON only, only using the fields defined by the log_analyzer function. I only need the response, no additional text. Don't generate a subject line. Instead of using placeholders, just leave out the placeholder brackets. You're allowed to use line breaks in your answer."},
            {"role": "system", "content": "IMPORTANT: Analyze EVERY line in the log file. Return ALL suspicious entries you find, not just a few examples."},
            {"role": "user", "content": "Analyse the following Log-Rows and give the results with the tool 'log_analyzer'."
                                        "Log: " + logText}
        ]

    def create_and_send_request(self, logText: str, hardened: bool):
        response = self.client.chat.completions.create(
            model=self.model,
            response_format={"type": "json_object"},
            messages=self.messages(logText, hardened),
            temperature=0.0,
            top_p=1.0,
            tools=[
                {
                    "type": "function",
                    "function": {
                        "name": "log_analyzer",
                        "description": "Print a reformulated text.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "results": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "required": ["attackType", "confidence", "evidence", "line_no"],
                                        "properties": {
                                            "attackType": {
                                                "type": "string",
                                                "enum": ["SQLi", "XSS", "CmdInject", "DoS/DDoS"]
                                            },
                                            "confidence": {
                                                "type": "number",
                                                "minimum": 0.0,
                                                "maximum": 1.0
                                            },
                                            "evidence": {
                                                "type": "string",
                                                "description": "The suspicious content or pattern found in the log line"
                                            },
                                            "line_no": {"type": "integer", "minimum": 1}
                                        }
                                    }
                                }
                            },
                            "required": ["results"]
                        }
                    }
                }],
            tool_choice="required"
        )

        return response.choices[0].message.tool_calls[0].function.arguments

    def prepare_log_with_line_numbers(self, logText: str) -> str:
        lines = logText.split('\n')
        numbered_lines = [f"[LINE {i+1}] {line}" for i, line in enumerate(lines)]
        return '\n'.join(numbered_lines)


    def connect(self, logPath: Path, hardened: bool) -> tuple[list[LLMAnswer], float]:
        logText = logPath.read_text(encoding="utf-8")
        numbered_logText = self.prepare_log_with_line_numbers(logText)


        t0 = time.perf_counter()
        detections = self.create_and_send_request(numbered_logText, hardened)
        time_needed = time.perf_counter() - t0
        detections_json = json.loads(detections)
        results = detections_json.get("results", [])

        llm_answer: list[LLMAnswer] = []
        for i, det in enumerate(results):
            llm_answer.append(LLMAnswer(
                id=i,
                attackType=det.get("attackType", "UNKNOWN"),
                confidence=det.get("confidence", None),
                evidence=det.get("evidence", ""),
                line_no=det.get("line_no", None)
            ))

        return llm_answer, time_needed
