from __future__ import annotations

import json
import re
import sys
import tkinter as tk
from dataclasses import dataclass, field
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext
from typing import Dict, List, Optional, Set, Tuple

from bs4 import BeautifulSoup, Tag
import sys
from pathlib import Path

# ============================================================
# Config
# ============================================================


def get_resource_path(relative_path: str) -> Path:
    if hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / relative_path
    return Path(__file__).resolve().parent / relative_path

JSON_DIR_PATH = get_resource_path("SWE4_Json")
# ============================================================
# Data models
# ============================================================

@dataclass
class CoverageValue:
    covered: int = 0
    total: int = 0
    percent: float = 0.0
    raw: str = ""


@dataclass
class OverallResults:
    testcases_passed: int = 0
    testcases_total: int = 0
    expecteds_passed: int = 0
    expecteds_total: int = 0
    statements_covered: int = 0
    statements_total: int = 0
    statements_percent: float = 0.0
    branches_covered: int = 0
    branches_total: int = 0
    branches_percent: float = 0.0


@dataclass
class FunctionMetric:
    unit: str
    subprogram: str
    complexity: Optional[int]
    statements: CoverageValue
    branches: CoverageValue
    analysis_statements: Optional[CoverageValue] = None
    analysis_branches: Optional[CoverageValue] = None
    execution_statements: Optional[CoverageValue] = None
    execution_branches: Optional[CoverageValue] = None


@dataclass
class DataRow:
    level: int
    name: str
    data_type: str = ""
    value: str = ""


@dataclass
class TestCaseInfo:
    name: str
    unit_under_test: str = ""
    subprogram: str = ""
    date_of_creation: str = ""
    date_of_execution: str = ""
    file_name: str = ""
    execution_result: str = ""
    expected_results_summary: str = ""
    event_count: int = 0
    input_rows: List[DataRow] = field(default_factory=list)
    expected_rows: List[DataRow] = field(default_factory=list)


@dataclass
class ReportMeta:
    file_name: str
    layer: str = ""
    component: str = ""
    unit: str = ""


@dataclass
class ParsedReport:
    meta: ReportMeta
    overall: OverallResults
    metrics: List[FunctionMetric] = field(default_factory=list)
    testcases: List[TestCaseInfo] = field(default_factory=list)


@dataclass
class QualityResult:
    red_flags: List[str] = field(default_factory=list)
    yellow_flags: List[str] = field(default_factory=list)


# ============================================================
# Parsing helpers
# ============================================================

COVERAGE_RE = re.compile(r"(\d+)\s*/\s*(\d+)(?:\s*\((\d+(?:\.\d+)?)%\))?")
FILE_NAME_RE = re.compile(
    r"^(?P<layer>[^_]+)_(?P<component>[^_]+)_(?P<unit>.+?)_UT_Report\.html$",
    re.IGNORECASE,
)
NULL_RE = re.compile(r"<<\s*null\s*>>", re.IGNORECASE)

def is_valid_report_file_name(path: Path) -> bool:
    return FILE_NAME_RE.match(path.name) is not None

def clean_text(value: Optional[str]) -> str:
    if value is None:
        return ""
    return " ".join(value.replace("\xa0", " ").split())


def get_text(tag: Optional[Tag]) -> str:
    if tag is None:
        return ""
    return clean_text(tag.get_text(" ", strip=True))


def parse_coverage_text(text: str) -> CoverageValue:
    text = " ".join(text.split())
    match = COVERAGE_RE.search(text)
    if not match:
        return CoverageValue(raw=text)

    covered = int(match.group(1))
    total = int(match.group(2))
    if match.group(3) is not None:
        percent = float(match.group(3))
    else:
        percent = (covered / total * 100.0) if total else 0.0

    return CoverageValue(
        covered=covered,
        total=total,
        percent=percent,
        raw=text,
    )


def parse_file_meta(path: Path) -> ReportMeta:
    meta = ReportMeta(file_name=path.name)
    match = FILE_NAME_RE.match(path.name)
    if match:
        meta.layer = match.group("layer")
        meta.component = match.group("component")
        meta.unit = match.group("unit")
    return meta


def get_short_function_name(full_name: str) -> str:
    full_name = clean_text(full_name)
    if not full_name:
        return ""
    return full_name.split("::")[-1].strip()


# ============================================================
# Overall Results
# ============================================================

def parse_overall_results(soup: BeautifulSoup) -> OverallResults:
    result = OverallResults()

    def get_by_id(elem_id: str) -> str:
        tag = soup.find(id=elem_id)
        return clean_text(tag.get_text(" ", strip=True)) if tag else ""

    tc_text = get_by_id("overall-results-testcases")
    ex_text = get_by_id("overall-results-expecteds")
    st_text = get_by_id("overall-results-statements")
    br_text = get_by_id("overall-results-branches")

    tc_cov = parse_coverage_text(tc_text)
    ex_cov = parse_coverage_text(ex_text)
    st_cov = parse_coverage_text(st_text)
    br_cov = parse_coverage_text(br_text)

    result.testcases_passed = tc_cov.covered
    result.testcases_total = tc_cov.total
    result.expecteds_passed = ex_cov.covered
    result.expecteds_total = ex_cov.total
    result.statements_covered = st_cov.covered
    result.statements_total = st_cov.total
    result.statements_percent = st_cov.percent
    result.branches_covered = br_cov.covered
    result.branches_total = br_cov.total
    result.branches_percent = br_cov.percent

    return result


# ============================================================
# Metrics
# ============================================================

def is_analysis_or_execution_row(tds: List[Tag]) -> bool:
    if len(tds) < 2:
        return False
    subprogram_text = clean_text(tds[1].get_text(" ", strip=True)).lower()
    return subprogram_text in {"analysis", "execution"}


def parse_metrics(soup: BeautifulSoup) -> List[FunctionMetric]:
    metrics_header = soup.find(id="Metrics")
    if metrics_header is None:
        return []

    metrics_table = metrics_header.find_next("table")
    if metrics_table is None:
        return []

    metrics: List[FunctionMetric] = []
    current_metric: Optional[FunctionMetric] = None

    tbody = metrics_table.find("tbody")
    if tbody is None:
        return []

    for tr in tbody.find_all("tr", recursive=False):
        tds = tr.find_all("td", recursive=False)
        if len(tds) < 5:
            continue

        if is_analysis_or_execution_row(tds):
            if current_metric is None:
                continue

            kind = clean_text(tds[1].get_text(" ", strip=True)).lower()
            stmt_cov = parse_coverage_text(clean_text(tds[3].get_text(" ", strip=True)))
            br_cov = parse_coverage_text(clean_text(tds[4].get_text(" ", strip=True)))

            if kind == "analysis":
                current_metric.analysis_statements = stmt_cov
                current_metric.analysis_branches = br_cov
            elif kind == "execution":
                current_metric.execution_statements = stmt_cov
                current_metric.execution_branches = br_cov
            continue

        unit = clean_text(tds[0].get_text(" ", strip=True))
        subprogram = clean_text(tds[1].get_text(" ", strip=True))
        complexity_text = clean_text(tds[2].get_text(" ", strip=True))
        stmt_text = clean_text(tds[3].get_text(" ", strip=True))
        br_text = clean_text(tds[4].get_text(" ", strip=True))

        complexity = int(complexity_text) if complexity_text.isdigit() else None
        current_metric = FunctionMetric(
            unit=unit,
            subprogram=subprogram,
            complexity=complexity,
            statements=parse_coverage_text(stmt_text),
            branches=parse_coverage_text(br_text),
        )
        metrics.append(current_metric)

    return metrics


# ============================================================
# Test Cases
# ============================================================

def table_to_key_value(table: Optional[Tag]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    if table is None:
        return result

    for tr in table.find_all("tr"):
        th = tr.find("th")
        td = tr.find("td")
        if th and td:
            key = clean_text(th.get_text(" ", strip=True))
            value = clean_text(td.get_text(" ", strip=True))
            result[key] = value
    return result


def extract_table_rows(table: Optional[Tag]) -> List[Tuple[str, str, str, int]]:
    rows_out: List[Tuple[str, str, str, int]] = []
    if table is None:
        return rows_out

    tbody = table.find("tbody") or table
    rows = tbody.find_all("tr", recursive=False)

    for row in rows:
        tds = row.find_all("td", recursive=False)
        if not tds:
            continue

        vals = [get_text(td) for td in tds]
        while len(vals) < 3:
            vals.append("")

        level = 0
        for cls in tds[0].get("class", []):
            match = re.fullmatch(r"i(\d+)", str(cls))
            if match:
                level = int(match.group(1))
                break

        rows_out.append((vals[0], vals[1], vals[2], level))

    return rows_out


def filter_meaningful_rows(raw_rows: List[Tuple[str, str, str, int]]) -> List[DataRow]:
    filtered: List[DataRow] = []

    kept_instance_header = False
    keep_next_type_after_instance = False
    keep_next_type_after_return = False

    for c1, c2, c3, level in raw_rows:
        text = c1.strip()
        has_data = (c2.strip() != "" or c3.strip() != "")

        if text == "" and not has_data:
            continue

        if has_data:
            if text.startswith("UUT:") or text.startswith("Unit:") or text.startswith("Globals:"):
                continue
            filtered.append(DataRow(level=level, name=c1, data_type=c2, value=c3))
            continue

        if text == "class members":
            continue

        if text.startswith("UUT:") or text.startswith("Unit:") or text.startswith("Globals:"):
            continue

        if text.startswith("Subprogram:"):
            filtered.append(DataRow(level=level, name=c1, data_type=c2, value=c3))
            continue

        if text.startswith("Stubbed Subprograms"):
            filtered.append(DataRow(level=level, name=c1, data_type=c2, value=c3))
            continue

        if not kept_instance_header and text.endswith(" Instance"):
            filtered.append(DataRow(level=level, name=c1, data_type=c2, value=c3))
            kept_instance_header = True
            keep_next_type_after_instance = True
            continue

        if keep_next_type_after_instance:
            filtered.append(DataRow(level=level, name=c1, data_type=c2, value=c3))
            keep_next_type_after_instance = False
            continue

        if text == "return":
            filtered.append(DataRow(level=level, name=c1, data_type=c2, value=c3))
            keep_next_type_after_return = True
            continue

        if keep_next_type_after_return:
            filtered.append(DataRow(level=level, name=c1, data_type=c2, value=c3))
            keep_next_type_after_return = False
            continue

    return filtered


def compress_return_rows(rows: List[DataRow]) -> List[DataRow]:
    compressed: List[DataRow] = []
    i = 0

    while i < len(rows):
        row = rows[i]
        text = row.name.strip()

        if text == "return" and row.data_type.strip() == "" and row.value.strip() == "":
            if i + 1 < len(rows):
                next_row = rows[i + 1]
                next_text = next_row.name.strip()

                if (
                    next_text != ""
                    and next_row.data_type.strip() == ""
                    and next_row.value.strip() == ""
                    and not next_text.startswith("Subprogram:")
                    and not next_text.startswith("Stubbed Subprograms")
                    and not next_text.endswith(" Instance")
                    and next_text != "return"
                ):
                    compressed.append(
                        DataRow(
                            level=row.level,
                            name="return",
                            data_type=next_text,
                            value="",
                        )
                    )
                    i += 2
                    continue

        compressed.append(row)
        i += 1

    return compressed


def parse_data_table(table: Optional[Tag]) -> List[DataRow]:
    raw_rows = extract_table_rows(table)
    filtered_rows = filter_meaningful_rows(raw_rows)
    compressed_rows = compress_return_rows(filtered_rows)
    return compressed_rows


def parse_test_data_section(testcase_div: Tag) -> Dict[str, List[DataRow]]:
    result: Dict[str, List[DataRow]] = {
        "Input Test Data": [],
        "Expected Test Data": [],
    }

    direct_children = testcase_div.find_all("div", recursive=False)

    for block in direct_children:
        h3 = block.find("h3", recursive=False)
        if not h3:
            continue

        if get_text(h3) != "Test Case Data":
            continue

        subsections = block.find_all("div", recursive=False)
        for subsection in subsections:
            h4 = subsection.find("h4", recursive=False)
            if not h4:
                continue

            section_name = get_text(h4)
            if section_name not in result:
                continue

            table = subsection.find("table")
            if table is None:
                continue

            result[section_name] = parse_data_table(table)

        break

    return result


def parse_testcases(soup: BeautifulSoup) -> List[TestCaseInfo]:
    testcases: List[TestCaseInfo] = []

    for tc_div in soup.find_all("div", class_="testcase"):
        tc_name_tag = tc_div.find("span", class_="testcase_name")
        tc_name = clean_text(tc_name_tag.get_text(" ", strip=True)) if tc_name_tag else ""

        config_header = tc_div.find("a", id=re.compile(r"^TestCaseConfiguration_"))
        config_table = config_header.find_next("table") if config_header else None
        config_map = table_to_key_value(config_table)

        data_header = tc_div.find("a", id=re.compile(r"^TestCaseData_"))
        data_table = data_header.find_next("table") if data_header else None
        data_map = table_to_key_value(data_table)

        test_data = parse_test_data_section(tc_div)
        input_rows = test_data.get("Input Test Data", [])
        expected_rows = test_data.get("Expected Test Data", [])

        execution_header = tc_div.find("a", id=re.compile(r"^ExecutionResults_"))
        execution_result = ""
        if execution_header:
            h3 = execution_header.parent
            if h3 and h3.name == "h3":
                execution_result = clean_text(h3.get_text(" ", strip=True))

        event_count = len(tc_div.find_all("h4", class_="event"))

        expected_summary = ""
        result_div = tc_div.find("div", class_="testcase-result")
        if result_div:
            summary_table = result_div.find("table")
            if summary_table:
                first_success_row = summary_table.find("tr")
                if first_success_row:
                    expected_summary = clean_text(first_success_row.get_text(" | ", strip=True))

        info = TestCaseInfo(
            name=tc_name,
            unit_under_test=config_map.get("Unit Under Test", ""),
            subprogram=config_map.get("Subprogram", ""),
            date_of_creation=config_map.get("Date of Creation", ""),
            date_of_execution=config_map.get("Date of Execution", ""),
            file_name=data_map.get("File Name", ""),
            execution_result=execution_result,
            expected_results_summary=expected_summary,
            event_count=event_count,
            input_rows=input_rows,
            expected_rows=expected_rows,
        )
        testcases.append(info)

    return testcases


# ============================================================
# Report parser
# ============================================================

def parse_report(path: Path) -> ParsedReport:
    html_text = path.read_text(encoding="utf-8", errors="ignore")
    soup = BeautifulSoup(html_text, "html.parser")

    meta = parse_file_meta(path)
    overall = parse_overall_results(soup)
    metrics = parse_metrics(soup)
    testcases = parse_testcases(soup)

    return ParsedReport(
        meta=meta,
        overall=overall,
        metrics=metrics,
        testcases=testcases,
    )


# ============================================================
# JSON helpers
# ============================================================

def load_layer_function_map(layer: str, json_dir: Path) -> Dict[str, Dict[str, List[str]]]:
    json_path = json_dir / f"{layer.upper()}_FunctionList.json"
    if not json_path.exists():
        return {}

    with json_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    normalized: Dict[str, Dict[str, List[str]]] = {}
    for component, unit_map in data.items():
        comp_key = clean_text(component).lower()
        normalized[comp_key] = {}
        for unit, functions in unit_map.items():
            unit_key = clean_text(unit).lower()
            normalized[comp_key][unit_key] = [clean_text(str(x)) for x in functions]
    return normalized


def build_component_unit_candidates(meta: ReportMeta) -> List[Tuple[str, str]]:
    candidates: List[Tuple[str, str]] = []

    parsed_component = clean_text(meta.component)
    parsed_unit = clean_text(meta.unit)
    if parsed_component and parsed_unit:
        candidates.append((parsed_component, parsed_unit))

    file_name = clean_text(meta.file_name)
    layer = clean_text(meta.layer)
    if not file_name or not layer:
        return candidates

    middle_match = re.match(
        rf"^{re.escape(layer)}_(?P<middle>.+)_UT_Report\.html$",
        file_name,
        re.IGNORECASE,
    )
    if not middle_match:
        return candidates

    middle = clean_text(middle_match.group("middle"))
    parts = [part for part in middle.split("_") if part]
    for split_idx in range(1, len(parts)):
        component = "_".join(parts[:split_idx])
        unit = "_".join(parts[split_idx:])
        candidate = (component, unit)
        if candidate not in candidates:
            candidates.append(candidate)

    return candidates


def resolve_required_functions(
    report: ParsedReport,
    json_dir: Path,
) -> Tuple[List[str], Optional[Tuple[str, str]], List[Tuple[str, str]]]:
    return resolve_required_functions_from_meta(report.meta, json_dir)


def resolve_required_functions_from_meta(
    meta: ReportMeta,
    json_dir: Path,
) -> Tuple[List[str], Optional[Tuple[str, str]], List[Tuple[str, str]]]:
    layer_map = load_layer_function_map(meta.layer, json_dir)
    candidates = build_component_unit_candidates(meta)
    if not layer_map:
        return [], None, candidates

    for component, unit in candidates:
        comp_key = clean_text(component).lower()
        unit_key = clean_text(unit).lower()
        comp_map = layer_map.get(comp_key, {})
        if not comp_map:
            continue

        required = comp_map.get(unit_key, [])
        if required:
            return required, (component, unit), candidates

    return [], None, candidates


def get_required_functions(report: ParsedReport, json_dir: Path) -> List[str]:
    required, _, _ = resolve_required_functions(report, json_dir)
    return required


# ============================================================
# Quality checks
# ============================================================

def has_null_expected(tc: TestCaseInfo) -> bool:
    for row in tc.expected_rows:
        if NULL_RE.search(row.value):
            return True
    return False


def has_no_expected(tc: TestCaseInfo) -> bool:
    return len(tc.expected_rows) == 0


def get_functions_with_no_expected(testcases: List[TestCaseInfo]) -> List[str]:
    grouped: Dict[str, List[TestCaseInfo]] = {}
    for tc in testcases:
        subprogram = clean_text(tc.subprogram)
        if not subprogram:
            continue
        grouped.setdefault(subprogram, []).append(tc)

    functions_with_no_expected: List[str] = []
    for subprogram, tc_list in grouped.items():
        if all(has_no_expected(tc) for tc in tc_list):
            functions_with_no_expected.append(subprogram)

    return sorted(functions_with_no_expected)


def build_row_signature(rows: List[DataRow]) -> List[Tuple[str, str, str]]:
    signature: List[Tuple[str, str, str]] = []
    for row in rows:
        signature.append(
            (
                clean_text(row.name).lower(),
                clean_text(row.data_type).lower(),
                clean_text(row.value).lower(),
            )
        )
    return signature


def is_input_expected_identical(tc: TestCaseInfo) -> bool:
    if not tc.input_rows or not tc.expected_rows:
        return False
    return build_row_signature(tc.input_rows) == build_row_signature(tc.expected_rows)


def get_contextual_data_signatures(
    rows: List[DataRow],
) -> Set[Tuple[Tuple[str, ...], str, str, str]]:
    signatures: Set[Tuple[Tuple[str, ...], str, str, str]] = set()
    context_by_level: Dict[int, str] = {}

    for row in rows:
        level = row.level
        name = clean_text(row.name)
        data_type = clean_text(row.data_type)
        value = clean_text(row.value)

        # Keep hierarchy synchronized with current row level.
        for existing_level in sorted(list(context_by_level.keys()), reverse=True):
            if existing_level >= level:
                del context_by_level[existing_level]
        if name:
            context_by_level[level] = name.lower()

        # Compare only real value rows.
        if not data_type and not value:
            continue

        parent_path = tuple(
            context_by_level[idx]
            for idx in sorted(context_by_level.keys())
            if idx < level
        )
        signatures.add((parent_path, name.lower(), data_type.lower(), value.lower()))

    return signatures


def get_shared_contextual_inputs(
    tc: TestCaseInfo,
) -> Set[Tuple[Tuple[str, ...], str, str, str]]:
    input_signatures = get_contextual_data_signatures(tc.input_rows)
    expected_signatures = get_contextual_data_signatures(tc.expected_rows)
    return input_signatures & expected_signatures


def get_metric_short_names(metrics: List[FunctionMetric]) -> Set[str]:
    result: Set[str] = set()
    for metric in metrics:
        short_name = get_short_function_name(metric.subprogram)
        if short_name:
            result.add(short_name.lower())
    return result


def run_quality_checks(
    report: ParsedReport,
    json_dir: Path,
    required_functions: Optional[List[str]] = None,
) -> QualityResult:
    result = QualityResult()

    if report.overall.statements_percent < 100.0:
        result.red_flags.append(
            f"Overall Statement Coverage is not 100%: {report.overall.statements_covered} / {report.overall.statements_total} ({report.overall.statements_percent:.1f}%)"
        )

    if report.overall.branches_percent < 100.0:
        result.red_flags.append(
            f"Overall Branch Coverage is not 100%: {report.overall.branches_covered} / {report.overall.branches_total} ({report.overall.branches_percent:.1f}%)"
        )

    if required_functions is None:
        required_functions = get_required_functions(report, json_dir)
    metric_short_names = get_metric_short_names(report.metrics)
    missing_functions = [
        fn for fn in required_functions
        if clean_text(fn).lower() not in metric_short_names
    ]
    if missing_functions:
        result.red_flags.append(
            "Functions missing in Metrics: " + ", ".join(missing_functions)
        )

    for tc in report.testcases:
        if has_null_expected(tc):
            result.red_flags.append(
                f"Function '{tc.subprogram}' TC '{tc.name}' has <<NULL>> in Expected Values."
            )

        if tc.event_count > 200:
            result.red_flags.append(
                f"Function '{tc.subprogram}' TC '{tc.name}' has Event Count over 200, possible Infinite Loop: {tc.event_count}."
            )

        if not has_no_expected(tc) and is_input_expected_identical(tc):
            result.yellow_flags.append(
                f"Function '{tc.subprogram}' TC '{tc.name}' has identical Input and Expected Values."
            )
        elif not has_no_expected(tc):
            shared_inputs = get_shared_contextual_inputs(tc)
            for parent_path, name, data_type, value in sorted(shared_inputs):
                parent_text = " > ".join(parent_path) if parent_path else "(root)"
                result.yellow_flags.append(
                    f"Function '{tc.subprogram}' TC '{tc.name}' has same Input/Expected value under '{parent_text}': {name}/{data_type}/{value}."
                )

    no_expected_functions = get_functions_with_no_expected(report.testcases)
    for subprogram in no_expected_functions:
        result.yellow_flags.append(
            f"Function '{subprogram}' has no Expected Values."
        )

    return result


# ============================================================
# GUI
# ============================================================

class ReportCertifierApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Vector Buddy_AlphaBuild")
        self.root.geometry("1200x780")
        self.root.minsize(980, 620)

        self.selected_file: Optional[Path] = None
        self.json_dir: Path = JSON_DIR_PATH

        self._build_ui()

    def _build_ui(self) -> None:
        self.root.grid_rowconfigure(3, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # Title
        title = tk.Label(
            self.root,
            text="Vector Buddy",
            font=("Segoe UI", 18, "bold"),
            anchor="w",
            padx=12,
            pady=10,
        )
        title.grid(row=0, column=0, sticky="ew")

        # Top controls
        top_frame = tk.Frame(self.root, padx=12, pady=8)
        top_frame.grid(row=1, column=0, sticky="ew")
        top_frame.grid_columnconfigure(1, weight=1)

        tk.Label(top_frame, text="HTML Report:", font=("Segoe UI", 10, "bold")).grid(
            row=0, column=0, sticky="w", padx=(0, 8)
        )

        self.file_var = tk.StringVar()
        self.file_entry = tk.Entry(top_frame, textvariable=self.file_var, state="readonly")
        self.file_entry.grid(row=0, column=1, sticky="ew", padx=(0, 8))

        self.browse_btn = tk.Button(
            top_frame,
            text="Browse",
            width=12,
            command=self.on_browse_file,
        )
        self.browse_btn.grid(row=0, column=2, padx=(0, 8))

        self.analyze_btn = tk.Button(
            top_frame,
            text="Analyze",
            width=12,
            command=self.on_analyze,
            state="disabled",
        )
        self.analyze_btn.grid(row=0, column=3)

        # Meta info
        info_frame = tk.LabelFrame(self.root, text="Report Info", padx=12, pady=10)
        info_frame.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 8))
        for i in range(7):
            info_frame.grid_columnconfigure(i, weight=1)

        tk.Label(info_frame, text="File:", font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w")
        tk.Label(info_frame, text="Layer:", font=("Segoe UI", 10, "bold")).grid(row=1, column=0, sticky="w")
        tk.Label(info_frame, text="Component:", font=("Segoe UI", 10, "bold")).grid(row=1, column=2, sticky="w")
        tk.Label(info_frame, text="Unit:", font=("Segoe UI", 10, "bold")).grid(row=1, column=4, sticky="w")

        self.file_name_label = tk.Label(info_frame, text="-", anchor="w", fg="#1f2937")
        self.file_name_label.grid(row=0, column=1, columnspan=6, sticky="w")

        self.layer_label = tk.Label(info_frame, text="-", anchor="w", fg="#1d4ed8")
        self.layer_label.grid(row=1, column=1, sticky="w")

        self.component_label = tk.Label(info_frame, text="-", anchor="w", fg="#1d4ed8")
        self.component_label.grid(row=1, column=3, sticky="w")

        self.unit_label = tk.Label(info_frame, text="-", anchor="w", fg="#1d4ed8")
        self.unit_label.grid(row=1, column=5, sticky="w")

        # Result area
        result_frame = tk.LabelFrame(self.root, text="Analyze Result", padx=8, pady=8)
        result_frame.grid(row=3, column=0, sticky="nsew", padx=12, pady=(0, 12))
        result_frame.grid_rowconfigure(1, weight=1)
        result_frame.grid_columnconfigure(0, weight=1)

        summary_frame = tk.Frame(result_frame)
        summary_frame.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        summary_frame.grid_columnconfigure(0, weight=1)

        self.summary_label = tk.Label(
            summary_frame,
            text="Select one HTML report file and run Analyze.",
            anchor="w",
            justify="left",
            font=("Segoe UI", 10),
        )
        self.summary_label.grid(row=0, column=0, sticky="ew")

        self.result_text = scrolledtext.ScrolledText(
            result_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            state="disabled",
        )
        self.result_text.grid(row=1, column=0, sticky="nsew")

        self._setup_text_tags()

    def _setup_text_tags(self) -> None:
        self.result_text.tag_config("header", font=("Segoe UI", 11, "bold"))
        self.result_text.tag_config("subheader", font=("Segoe UI", 10, "bold"))
        self.result_text.tag_config("normal", foreground="#111827")
        self.result_text.tag_config("good", foreground="#065f46")
        self.result_text.tag_config("red", foreground="#b91c1c")
        self.result_text.tag_config("yellow", foreground="#a16207")
        self.result_text.tag_config("muted", foreground="#6b7280")
        self.result_text.tag_config("divider", foreground="#9ca3af")

    def _set_result_text_state(self, state: str) -> None:
        self.result_text.configure(state=state)

    def _clear_result(self) -> None:
        self._set_result_text_state("normal")
        self.result_text.delete("1.0", tk.END)
        self._set_result_text_state("disabled")

    def _append_text(self, text: str, tag: str = "normal") -> None:
        self._set_result_text_state("normal")
        self.result_text.insert(tk.END, text, tag)
        self._set_result_text_state("disabled")

    def on_browse_file(self) -> None:
        file_path = filedialog.askopenfilename(
            title="Select HTML Report",
            filetypes=[
                ("HTML Files", "*.html"),
                ("All Files", "*.*"),
            ],
        )
        if not file_path:
            return

        selected = Path(file_path)
        self.selected_file = selected
        self.file_var.set(str(selected))

        self._clear_result()

        if not is_valid_report_file_name(selected):
            self.file_name_label.config(text=selected.name)
            self.layer_label.config(text="(invalid)")
            self.component_label.config(text="(invalid)")
            self.unit_label.config(text="(invalid)")

            self.summary_label.config(
                text="Invalid report naming detected."
            )

            self._append_text("Invalid file name format.\n", "red")
            self._append_text(
                "Expected format: LAYER_COMPONENT_UNIT_UT_Report.html\n",
                "red",
            )
            self._append_text(
                f"Selected file: {selected.name}\n",
                "muted",
            )
            self._append_text(
                "Please select a report file following the naming convention.\n",
                "muted",
            )

            self.analyze_btn.config(state="disabled")
            return

        meta = parse_file_meta(selected)
        required_functions, matched_pair, candidates = resolve_required_functions_from_meta(meta, self.json_dir)
        if matched_pair:
            resolved_component, resolved_unit = matched_pair
            meta.component = resolved_component
            meta.unit = resolved_unit

        self.file_name_label.config(text=meta.file_name or "-")
        self.layer_label.config(text=meta.layer or "(unknown)")
        self.component_label.config(text=meta.component or "(unknown)")
        self.unit_label.config(text=meta.unit or "(unknown)")

        self.summary_label.config(
            text=(
                f"Selected report: "
                f"Layer={meta.layer or '(unknown)'}, "
                f"Component={meta.component or '(unknown)'}, "
                f"Unit={meta.unit or '(unknown)'}"
            )
        )

        if not required_functions:
            tried_text = ", ".join([f"{comp}/{unit}" for comp, unit in candidates]) or "(none)"
            self._append_text("Component/Unit mapping not found in JSON.\n", "red")
            self._append_text(
                "Please check if report file has correct Component/Unit names.\n",
                "red",
            )
            self._append_text(
                f"Tried candidates: {tried_text}\n",
                "muted",
            )
            self.analyze_btn.config(state="disabled")
            return

        self._append_text("File loaded successfully.\n", "good")
        self._append_text("Press Analyze to run quality checks.\n", "muted")

        self.analyze_btn.config(state="normal")

    def on_analyze(self) -> None:
        if self.selected_file is None:
            messagebox.showwarning("No File", "Please select one HTML report file first.")
            return

        if not self.selected_file.exists():
            messagebox.showerror("File Error", "Selected file does not exist.")
            return

        if not is_valid_report_file_name(self.selected_file):
            self._clear_result()
            self.summary_label.config(text="Analyze failed due to invalid report naming.")
            self._append_text("Analyze aborted.\n", "red")
            self._append_text(
                "File name must follow: LAYER_COMPONENT_UNIT_UT_Report.html\n",
                "red",
            )
            self._append_text(f"Current file: {self.selected_file.name}\n", "muted")
            return

        try:
            report = parse_report(self.selected_file)
            required_functions, matched_pair, candidates = resolve_required_functions(report, self.json_dir)
            if not required_functions:
                parsed_component = report.meta.component or "(unknown)"
                parsed_unit = report.meta.unit or "(unknown)"
                tried_text = ", ".join([f"{comp}/{unit}" for comp, unit in candidates]) or "(none)"
                messagebox.showerror(
                    "Mapping Error",
                    (
                        "Could not find Component/Unit mapping in JSON.\n"
                        f"Layer: {report.meta.layer or '(unknown)'}\n"
                        f"Parsed: {parsed_component}/{parsed_unit}\n"
                        f"Tried: {tried_text}\n"
                        "Please check report filename or JSON function list."
                    ),
                )
                return

            if matched_pair:
                resolved_component, resolved_unit = matched_pair
                self.component_label.config(text=resolved_component)
                self.unit_label.config(text=resolved_unit)
                report.meta.component = resolved_component
                report.meta.unit = resolved_unit

            quality = run_quality_checks(
                report,
                self.json_dir,
                required_functions=required_functions,
            )
            self.render_analysis(report, quality)
        except Exception as exc:
            messagebox.showerror("Analyze Error", str(exc))

    def render_analysis(self, report: ParsedReport, quality: QualityResult) -> None:
        self._clear_result()

        red_count = len(quality.red_flags)
        yellow_count = len(quality.yellow_flags)

        self.summary_label.config(
            text=(
                f"Analyze completed | "
                f"TestCases: {len(report.testcases)} | "
                f"Metrics: {len(report.metrics)} | "
                f"Red Flags: {red_count} | "
                f"Yellow Flags: {yellow_count}"
            )
        )

        self._append_text("Report Summary\n", "header")
        self._append_text("=" * 90 + "\n", "divider")
        self._append_text(f"File       : {report.meta.file_name}\n", "normal")
        self._append_text(f"Layer      : {report.meta.layer or '(unknown)'}\n", "normal")
        self._append_text(f"Component  : {report.meta.component or '(unknown)'}\n", "normal")
        self._append_text(f"Unit       : {report.meta.unit or '(unknown)'}\n", "normal")
        self._append_text("\n", "normal")

        self._append_text("Overall Results\n", "subheader")
        self._append_text("-" * 90 + "\n", "divider")
        self._append_text(
            f"TestCases   : {report.overall.testcases_passed} / {report.overall.testcases_total}\n",
            "normal",
        )
        self._append_text(
            f"Expecteds   : {report.overall.expecteds_passed} / {report.overall.expecteds_total}\n",
            "normal",
        )
        stmt_tag = "good" if report.overall.statements_percent >= 100.0 else "red"
        br_tag = "good" if report.overall.branches_percent >= 100.0 else "red"

        self._append_text(
            f"Statements  : {report.overall.statements_covered} / {report.overall.statements_total} "
            f"({report.overall.statements_percent:.1f}%)\n",
            stmt_tag,
        )
        self._append_text(
            f"Branches    : {report.overall.branches_covered} / {report.overall.branches_total} "
            f"({report.overall.branches_percent:.1f}%)\n",
            br_tag,
        )
        self._append_text("\n", "normal")

        self._append_text("Red Flags\n", "subheader")
        self._append_text("-" * 90 + "\n", "divider")
        if quality.red_flags:
            for idx, msg in enumerate(quality.red_flags, start=1):
                self._append_text(f"{idx}. {msg}\n", "red")
        else:
            self._append_text("None\n", "good")
        self._append_text("\n", "normal")

        self._append_text("Yellow Flags\n", "subheader")
        self._append_text("-" * 90 + "\n", "divider")
        if quality.yellow_flags:
            for idx, msg in enumerate(quality.yellow_flags, start=1):
                self._append_text(f"{idx}. {msg}\n", "yellow")
        else:
            self._append_text("None\n", "good")

        self.result_text.see("1.0")


# ============================================================
# Main
# ============================================================

def main() -> None:
    try:
        root = tk.Tk()
        app = ReportCertifierApp(root)
        root.mainloop()
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
