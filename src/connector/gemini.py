import json
import os
import time
from pathlib import Path

import google.generativeai as genai
from dotenv import load_dotenv

from src.utils.models import LLMAnswer
from .baseConnector import Connector


class Gemini(Connector):
    load_dotenv()

    attack_types_path = Path("./connector/structure/attack_types.json")
    attack_types = json.loads(attack_types_path.resolve().read_text(encoding="utf-8"))
    attack_types_summary = "; ".join(f"{k}: {v['description']}" for k, v in attack_types["AttackTypes"].items())

    system_prompts_path = Path("./connector/structure/system_prompts.json")
    system_prompts = json.loads(system_prompts_path.resolve().read_text(encoding="utf-8"))

    def __init__(self, model: str):
        try:
            genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
        except TypeError:
            print("Fehler: Der GOOGLE_API_KEY wurde nicht gefunden. Stelle sicher, dass er in deiner .env-Datei gesetzt ist.")
            exit()

        log_analyzer_tool = {
            "name": "log_analyzer",
            "description": "Gibt die Analyseergebnisse für die Log-Daten aus.",
            "parameters": {
                "type": "OBJECT",
                "properties": {
                    "results": {
                        "type": "ARRAY",
                        "items": {
                            "type": "OBJECT",
                            "required": ["attackType", "confidence", "evidence", "line_no"],
                            "properties": {
                                "attackType": {
                                    "type": "STRING",
                                    "enum": ["SQLi", "XSS", "CmdInject", "DoS/DDoS"]
                                },
                                "confidence": { "type": "NUMBER" },
                                "evidence": { "type": "STRING" },
                                "line_no": { "type": "INTEGER" }
                            }
                        }
                    }
                },
                "required": ["results"]
            }
        }
        system_instructions = (
            f"Use the AttackTypes summary below as DEFINITIONS ONLY. \n AttackTypes summary: {self.attack_types_summary}"
            "Return JSON only, only using the fields defined by the log_analyzer function. I only need the response, no additional text. Don't generate a subject line. Instead of using placeholders, just leave out the placeholder brackets. You're allowed to use line breaks in your answer."
            "IMPORTANT: Analyze EVERY line in the log file. Return ALL suspicious entries you find, not just a few examples."
        )

        generation_config = genai.types.GenerationConfig(
            temperature=0.0,
            top_p=1.0,
        )

        self.model = genai.GenerativeModel(
            model_name=model,
            system_instruction=system_instructions,
            generation_config=generation_config,
            tools=[log_analyzer_tool]
        )

    def create_and_send_request(self, logText: str, hardened: bool) -> str:
        system_content = self.system_prompts["system_prompts"]["hardened" if hardened else "normal"]

        user_prompt = (
                f"{system_content}\n "
                "Analyse the following Log-Rows and give the results with the tool 'log_analyzer'.\n"
                "Log:\n" + logText
        )
        response = self.model.generate_content(
            user_prompt,
            tool_config={'function_calling_config': {'mode': 'ANY'}}
        )

        function_call = response.candidates[0].content.parts[0].function_call
        if function_call.name == "log_analyzer":
            args_dict = dict(function_call.args)
            results_list = [dict(item) for item in args_dict.get("results", [])]

            final_data = {"results": results_list}

            return json.dumps(final_data)
        else:
            raise Exception("Kein 'log_analyzer'-Tool wurde verwendet.")

    def prepare_log_with_line_numbers(self, logText: str) -> str:
        lines = logText.strip().split('\n')
        numbered_lines = [f"[LINE {i+1}] {line}" for i, line in enumerate(lines)]
        return '\n'.join(numbered_lines)

    def connect(self, logPath: Path, hardened: bool) -> tuple[list[LLMAnswer], float]:
        logText = logPath.read_text(encoding="utf-8")
        numbered_logText = self.prepare_log_with_line_numbers(logText)

        t0 = time.perf_counter()
        detections_str = self.create_and_send_request(numbered_logText, hardened)
        time_needed = time.perf_counter() - t0

        detections_json = json.loads(detections_str)
        results = detections_json.get("results", [])

        llm_answer: list[LLMAnswer] = []
        for i, det in enumerate(results):
            llm_answer.append(LLMAnswer(
                id=i,
                attackType=det.get("attackType", "UNKNOWN"),
                confidence=det.get("confidence", 0.0),
                evidence=det.get("evidence", ""),
                line_no=det.get("line_no", 0)
            ))

        return llm_answer, time_needed