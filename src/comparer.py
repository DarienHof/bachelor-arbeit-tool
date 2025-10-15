from pathlib import Path
from typing import get_args

from src.utils.fileHelper import write_lines, ensure_dir
from src.utils.models import LLMAnswer, SanitizeRecord, InjectionRecord, ComparisonResult, AttackType


class Comparer:
    llm_results_global_injected: dict[str, dict[str, ComparisonResult]] = {}
    llm_results_per_package_injected: dict[str, dict[str, ComparisonResult]]= {}

    llm_results_global_sanitized: dict[str, dict[str, ComparisonResult]] = {}
    llm_results_per_package_sanitized: dict[str, dict[str, ComparisonResult]] = {}
    sanitized_number_of_entries: dict[str, dict[str, int]] = {}

    llm_results_global_sanitized_filtered: dict[str, dict[str, ComparisonResult]] = {}
    llm_results_per_package_sanitized_filtered: dict[str, dict[str, ComparisonResult]] = {}
    sanitized_filtered_number_of_entries: dict[str, dict[str, int]] = {}

    def compare(self,
                outputPath: Path,
                packageIndex: int,
                injections: list[InjectionRecord],
                answersInjected: dict[str, tuple[list[LLMAnswer], float]],
                sanatizeRecords: list[SanitizeRecord],
                answersSanitized: list[dict[str, tuple[list[LLMAnswer], float]]]) -> None:

        cr_injected = self.do_compare(outputPath, "injected", injections, answersInjected)
        cr_sanatized, cr_list_filtered = self.compare_sanitized(outputPath, sanatizeRecords, answersSanitized)

        print("#"*50)
        print(f"Package {packageIndex} finished")
        print(f"Injected: {cr_injected}")
        for cr in cr_sanatized:
            print(f"Sanatized: {cr}")
        for cr in cr_list_filtered:
            print(f"Sanatized Filtered: {cr}")
        print("#"*50)

        self.complete_package_injected(outputPath.joinpath(f"package_{packageIndex}_injected.txt"))
        self.complete_package_sanitized(outputPath.joinpath(f"package_{packageIndex}_sanitized.txt"))
        self.complete_package_sanitized_filtered(outputPath.joinpath(f"package_{packageIndex}_sanitized_filtered.txt"))


        return None

    def completeTest(self, outputPath: Path, extra: str) -> None:
        outputLines = []
        csv_lines = ["Model,Type,True_Positives,False_Negatives,False_Positives,Precision,Recall,F1_Score,Total_Time"]
        csv_attack_lines = ["AttackType,Model,Type,True_Positives,False_Negatives,False_Positives,Precision,Recall,F1_Score"]

        for model in self.llm_results_global_injected:
            result = ComparisonResult(0, 0, 0)
            for attackType in self.llm_results_global_injected[model]:
                resultLocal = self.llm_results_global_injected[model][attackType]
                csv_attack_lines.append(f"{attackType},{model},Injected,{resultLocal.true_positives},{resultLocal.false_negatives},{resultLocal.false_positives},{resultLocal.precision()},{resultLocal.recall()},{resultLocal.f1_score()}")

                result.true_positives += resultLocal.true_positives
                result.false_negatives += resultLocal.false_negatives
                result.false_positives += resultLocal.false_positives
                result.time_needed = resultLocal.time_needed


            csv_lines.append(f"{model},Injected,{result.true_positives},{result.false_negatives},{result.false_positives},{result.precision()},{result.recall()},{result.f1_score()},{result.time_needed}")
            outputLines.append(f"Injected Model: {model}; {str(result)}")

        for model in self.llm_results_global_sanitized:
            result = ComparisonResult(0, 0, 0)
            for attackType in self.llm_results_global_sanitized[model]:
                resultLocal = self.llm_results_global_sanitized[model][attackType]
                csv_attack_lines.append(f"{attackType},{model},Sanitized,{resultLocal.true_positives},{resultLocal.false_negatives},{resultLocal.false_positives},{resultLocal.precision()},{resultLocal.recall()},{resultLocal.f1_score()}")

                result.true_positives += resultLocal.true_positives
                result.false_negatives += resultLocal.false_negatives
                result.false_positives += resultLocal.false_positives
                result.time_needed = resultLocal.time_needed


            csv_lines.append(f"{model},Sanitized,{result.true_positives},{result.false_negatives},{result.false_positives},{result.precision()},{result.recall()},{result.f1_score()},{result.time_needed}")
            outputLines.append(f"Sanitized Model: {model}; {str(result)}")

        for model in self.llm_results_global_sanitized_filtered:
            result = ComparisonResult(0, 0, 0)
            for attackType in self.llm_results_global_sanitized_filtered[model]:
                resultLocal = self.llm_results_global_sanitized_filtered[model][attackType]
                csv_attack_lines.append(f"{attackType},{model},Sanitized_Filtered,{resultLocal.true_positives},{resultLocal.false_negatives},{resultLocal.false_positives},{resultLocal.precision()},{resultLocal.recall()},{resultLocal.f1_score()}")

                result.true_positives += resultLocal.true_positives
                result.false_negatives += resultLocal.false_negatives
                result.false_positives += resultLocal.false_positives
                result.time_needed = resultLocal.time_needed


            csv_lines.append(f"{model},Sanitized_Filtered,{result.true_positives},{result.false_negatives},{result.false_positives},{result.precision()},{result.recall()},{result.f1_score()},{result.time_needed}")
            outputLines.append(f"Sanitized Model Filtered: {model}; {str(result)}")

        output_file = outputPath.joinpath(f"{extra}_complete_test_results.txt")
        write_lines(output_file, outputLines)

        csv_file = outputPath.joinpath(f"{extra}_complete_test_results.csv")
        write_lines(csv_file, csv_lines)

        csv_file = outputPath.joinpath(f"{extra}_complete_attacktype_test_results.csv")
        write_lines(csv_file, csv_attack_lines)

        self.llm_results_global_injected: dict[str, dict[str, ComparisonResult]] = {}
        self.llm_results_global_sanitized: dict[str, dict[str, ComparisonResult]] = {}
        self.llm_results_global_sanitized_filtered: dict[str, dict[str, ComparisonResult]] = {}



    def do_compare(self,
                         outputPath: Path,
                         extra: str,
                         injections: list[InjectionRecord],
                         answersInjected: dict[str, tuple[list[LLMAnswer], float]],
                         sanitize: bool = False,
                         filtered: bool = False) -> list[ComparisonResult]:
        cr_list = []


        for attackType in get_args(AttackType):
            if attackType == "UNKNOWN":
                continue


            injection_map = {injection.line_no: injection for injection in injections if injection.attack_type == attackType}
            injection_line_nos = set(injection_map.keys())

            for model, answers_and_time in answersInjected.items():
                answers, time = answers_and_time
                answer_map = {answer.line_no: answer for answer in answers if answer.line_no is not None and answer.attackType == attackType}
                answer_line_nos = set(answer_map.keys())

                diff_FP = answer_line_nos.difference(injection_line_nos)
                diff_FN = injection_line_nos.difference(answer_line_nos)
                true_positives_lines = answer_line_nos.intersection(injection_line_nos)

                TP = len(true_positives_lines)
                FN = len(diff_FN)
                FP = len(diff_FP)

                cr = ComparisonResult(TP, FN, FP, time)
                cr_list.append(cr)

                output_lines = [str(cr)]

                if TP > 0:
                    output_lines.append("True Positives (korrekt erkannt):")
                    for line_no in sorted(true_positives_lines):
                        payload = injection_map[line_no].payload
                        attack_type = injection_map[line_no].attack_type
                        output_lines.append(f"  Line {line_no}: {attack_type} - {payload}")
                    output_lines.append("")

                if FN > 0:
                    output_lines.append("False Negatives (nicht erkannt):")
                    for line_no in sorted(diff_FN):
                        payload = injection_map[line_no].payload
                        attack_type = injection_map[line_no].attack_type
                        output_lines.append(f"  Line {line_no}: {attack_type} - {payload}")
                    output_lines.append("")

                if FP > 0:
                    output_lines.append("False Positives (fälschlicherweise erkannt):")
                    for line_no in sorted(diff_FP):
                        payload = answer_map[line_no].evidence
                        output_lines.append(f"  Line {line_no}: {payload}")

                if len(answers) > 0:
                    output_lines.append("Alle Modell Antworten:")
                    for line_no in sorted(answer_map.keys()):
                        answer = answer_map[line_no]
                        output_lines.append(f"  Line {line_no}: {answer.evidence} erkannt als {answer.attackType} mit der Sicherheit von {answer.confidence}")
                    output_lines.append("")


                write_path = outputPath.joinpath(f"{attackType.replace("/", "")}_{model}_{extra}.txt")
                write_lines(write_path, output_lines)

                if sanitize:
                    if filtered:
                        self.update_model_sanitized_filtered(model, attackType, cr)
                    else:
                        self.update_model_sanitized(model, attackType, cr)
                else:
                    self.update_model_injected(model, attackType, cr)

        return cr_list

    def compare_sanitized(self,
                          outputPath: Path,
                          sanitizeRecords: list[SanitizeRecord],
                          answersSanitized: list[dict[str, tuple[list[LLMAnswer], float]]]) -> tuple[
        list[ComparisonResult], list[ComparisonResult]]:
        cr_list = []
        cr_list_filtered = []
        for i, sanitizeRecord in enumerate(sanitizeRecords):
            camouflage_line_nos = {camouflage.line_no for camouflage in sanitizeRecord.camouflageRecords}
            new_injections: list[InjectionRecord] = [
                *sanitizeRecord.injectionRecords,
                *[
                    InjectionRecord(
                        line_no=camouflage.line_no,
                        attack_type="Sanitize",
                        payload=camouflage.camouflage
                    )
                    for camouflage in sanitizeRecord.camouflageRecords
                ]
            ]

            answer_dict = answersSanitized[i]
            filtered_answers_dict: dict[str, tuple[list[LLMAnswer], float]] = {
                model: (
                    [answer for answer in answers if answer.line_no not in camouflage_line_nos],
                    time
                )
                for model, (answers, time) in answer_dict.items()
            }

            new_outputPath = outputPath.joinpath(f"sanitized_{i}")
            ensure_dir(new_outputPath)

            cr_list.append(self.do_compare(new_outputPath, f"normal", new_injections, answer_dict, True))
            cr_list_filtered.append(self.do_compare(new_outputPath, f"filtered", sanitizeRecord.injectionRecords, filtered_answers_dict, True, True))

        return cr_list, cr_list_filtered




    def update_model_injected(self, model: str, attackType: str, result: ComparisonResult) -> None:
        if model not in self.llm_results_per_package_injected:
            self.llm_results_per_package_injected[model] = {}
        if attackType not in self.llm_results_per_package_injected[model]:
            self.llm_results_per_package_injected[model][attackType] = ComparisonResult(0, 0, 0)
        self.llm_results_per_package_injected[model][attackType].true_positives += result.true_positives
        self.llm_results_per_package_injected[model][attackType].false_negatives += result.false_negatives
        self.llm_results_per_package_injected[model][attackType].false_positives += result.false_positives
        self.llm_results_per_package_injected[model][attackType].time_needed += result.time_needed

    def complete_package_injected(self, outputPath: Path) -> None:
        outputLines = []
        for model in self.llm_results_per_package_injected:
            if model not in self.llm_results_global_injected:
                self.llm_results_global_injected[model] = {}
            for attackType in self.llm_results_per_package_injected[model]:
                if attackType not in self.llm_results_global_injected[model]:
                    self.llm_results_global_injected[model][attackType] = ComparisonResult(0, 0, 0)
                self.llm_results_global_injected[model][attackType].true_positives += self.llm_results_per_package_injected[model][attackType].true_positives
                self.llm_results_global_injected[model][attackType].false_negatives += self.llm_results_per_package_injected[model][attackType].false_negatives
                self.llm_results_global_injected[model][attackType].false_positives += self.llm_results_per_package_injected[model][attackType].false_positives
                self.llm_results_global_injected[model][attackType].time_needed += self.llm_results_per_package_injected[model][attackType].time_needed

                outputLines.append(f"Model: {model}; AttackType: {attackType}; {str(self.llm_results_per_package_injected[model][attackType])}")
        self.llm_results_per_package_injected = {}
        write_lines(outputPath, outputLines)

    def update_model_sanitized(self, model: str, attackType: str, result: ComparisonResult) -> None:
        if model not in self.llm_results_per_package_sanitized:
            self.llm_results_per_package_sanitized[model] = {}
            self.sanitized_number_of_entries[model] = {}
        if attackType not in self.llm_results_per_package_sanitized[model]:
            self.llm_results_per_package_sanitized[model][attackType] = ComparisonResult(0, 0, 0)
            self.sanitized_number_of_entries[model][attackType] = 0
        self.llm_results_per_package_sanitized[model][attackType].true_positives += result.true_positives
        self.llm_results_per_package_sanitized[model][attackType].false_negatives += result.false_negatives
        self.llm_results_per_package_sanitized[model][attackType].false_positives += result.false_positives
        self.llm_results_per_package_sanitized[model][attackType].time_needed += result.time_needed
        self.sanitized_number_of_entries[model][attackType] += 1

    def complete_package_sanitized(self, outputPath: Path) -> None:
        outputLines = []
        for model in self.llm_results_per_package_sanitized:
            if model not in self.llm_results_global_sanitized:
                self.llm_results_global_sanitized[model] = {}
            for attackType in self.llm_results_per_package_sanitized[model]:
                if attackType not in self.llm_results_global_sanitized[model]:
                    self.llm_results_global_sanitized[model][attackType] = ComparisonResult(0, 0, 0)
                self.llm_results_global_sanitized[model][attackType].true_positives += self.llm_results_per_package_sanitized[model][attackType].true_positives / self.sanitized_number_of_entries[model][attackType]
                self.llm_results_global_sanitized[model][attackType].false_negatives += self.llm_results_per_package_sanitized[model][attackType].false_negatives / self.sanitized_number_of_entries[model][attackType]
                self.llm_results_global_sanitized[model][attackType].false_positives += self.llm_results_per_package_sanitized[model][attackType].false_positives / self.sanitized_number_of_entries[model][attackType]
                self.llm_results_global_sanitized[model][attackType].time_needed += self.llm_results_per_package_sanitized[model][attackType].time_needed / self.sanitized_number_of_entries[model][attackType]

                outputLines.append(f"Model: {model}; AttackType: {attackType}; {str(self.llm_results_per_package_sanitized[model][attackType])}")
        self.llm_results_per_package_sanitized = {}
        self.sanitized_number_of_entries = {}
        write_lines(outputPath, outputLines)

    def update_model_sanitized_filtered(self, model: str, attackType: str, result: ComparisonResult) -> None:
        if model not in self.llm_results_per_package_sanitized_filtered:
            self.llm_results_per_package_sanitized_filtered[model] = {}
            self.sanitized_filtered_number_of_entries[model] = {}
        if attackType not in self.llm_results_per_package_sanitized_filtered[model]:
            self.llm_results_per_package_sanitized_filtered[model][attackType] = ComparisonResult(0, 0, 0)
            self.sanitized_filtered_number_of_entries[model][attackType] = 0
        self.llm_results_per_package_sanitized_filtered[model][attackType].true_positives += result.true_positives
        self.llm_results_per_package_sanitized_filtered[model][attackType].false_negatives += result.false_negatives
        self.llm_results_per_package_sanitized_filtered[model][attackType].false_positives += result.false_positives
        self.llm_results_per_package_sanitized_filtered[model][attackType].time_needed += result.time_needed
        self.sanitized_filtered_number_of_entries[model][attackType] += 1

    def complete_package_sanitized_filtered(self, outputPath: Path) -> None:
        outputLines = []
        for model in self.llm_results_per_package_sanitized_filtered:
            if model not in self.llm_results_global_sanitized_filtered:
                self.llm_results_global_sanitized_filtered[model] = {}
            for attackType in self.llm_results_per_package_sanitized_filtered[model]:
                if attackType not in self.llm_results_global_sanitized_filtered[model]:
                    self.llm_results_global_sanitized_filtered[model][attackType] = ComparisonResult(0, 0, 0)
                self.llm_results_global_sanitized_filtered[model][attackType].true_positives += self.llm_results_per_package_sanitized_filtered[model][attackType].true_positives / self.sanitized_filtered_number_of_entries[model][attackType]
                self.llm_results_global_sanitized_filtered[model][attackType].false_negatives += self.llm_results_per_package_sanitized_filtered[model][attackType].false_negatives / self.sanitized_filtered_number_of_entries[model][attackType]
                self.llm_results_global_sanitized_filtered[model][attackType].false_positives += self.llm_results_per_package_sanitized_filtered[model][attackType].false_positives / self.sanitized_filtered_number_of_entries[model][attackType]
                self.llm_results_global_sanitized_filtered[model][attackType].time_needed += self.llm_results_per_package_sanitized_filtered[model][attackType].time_needed / self.sanitized_filtered_number_of_entries[model][attackType]

                outputLines.append(f"Model: {model}; AttackType: {attackType}; {str(self.llm_results_per_package_sanitized_filtered[model][attackType])}")
        self.llm_results_per_package_sanitized_filtered = {}
        self.sanitized_filtered_number_of_entries = {}
        write_lines(outputPath, outputLines)
