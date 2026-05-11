#!/usr/bin/env python3
"""Collect research software metrics into need_automic_metic.csv's wide layout.

The pipeline intentionally uses only Python's standard library plus the local
`git` executable. Secrets are read from .env and never written to outputs.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape


TODAY = dt.date.today()
DEFAULT_INPUT = "need_automic_metic.csv"
DEFAULT_OUTPUT_DIR = "outputs"
DEFAULT_REPOS_DIR = "repos"
DEFAULT_CACHE_DIR = ".cache/metrics"

SOURCE_TYPES = {
    "input": "input_csv",
    "github": "github_api",
    "git": "git_history",
    "files": "local_files",
    "heuristic": "heuristic",
    "ai": "ai_assisted",
    "deep": "deep_agent_review",
    "fallback": "fallback",
}

CODE_EXTS = {
    ".adb",
    ".ads",
    ".asm",
    ".bat",
    ".c",
    ".cc",
    ".cl",
    ".clj",
    ".cmake",
    ".cpp",
    ".cs",
    ".cu",
    ".cuh",
    ".cxx",
    ".dart",
    ".f",
    ".f03",
    ".f08",
    ".f77",
    ".f90",
    ".f95",
    ".go",
    ".groovy",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".java",
    ".jl",
    ".js",
    ".jsx",
    ".kt",
    ".lua",
    ".m",
    ".mm",
    ".pas",
    ".php",
    ".pl",
    ".pm",
    ".py",
    ".pyx",
    ".r",
    ".rb",
    ".rs",
    ".scala",
    ".sh",
    ".swift",
    ".ts",
    ".tsx",
    ".v",
    ".vh",
    ".xml",
}

TEXT_DOC_EXTS = {
    ".cfg",
    ".conf",
    ".css",
    ".csv",
    ".dockerfile",
    ".ini",
    ".json",
    ".lock",
    ".md",
    ".rst",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}

BINARY_HINT_EXTS = {
    ".7z",
    ".bmp",
    ".dll",
    ".dylib",
    ".exe",
    ".gif",
    ".gz",
    ".ico",
    ".jar",
    ".jpg",
    ".jpeg",
    ".mp4",
    ".pdf",
    ".png",
    ".so",
    ".tar",
    ".tiff",
    ".zip",
}

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".cache",
    ".idea",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "cmake-build-debug",
    "cmake-build-release",
    "dist",
    "node_modules",
}

AI_METRIC_KEYS = {
    "funding": {"contains": "How is the project funded?"},
    "platforms": {"contains": "Platforms?"},
    "performance": {"contains": "Is there evidence that performance was considered?"},
    "requirements": {"contains": "requirements specifications"},
    "correctness_tools": {"contains": "tools or techniques are used to build confidence"},
    "unexpected_input": {"contains": "unexpected/unanticipated input"},
    "newline_handling": {"contains": "plain text input files"},
    "coding_standard": {"contains": "Explicit identification of a coding standard"},
    "identifier_quality": {"contains": "code identifiers consistent"},
    "hard_coded_constants": {"contains": "constants (other than 0 and 1) hard coded"},
    "comment_clarity": {"contains": "Comments are clear"},
    "parameter_order": {"contains": "Parameters are in the same order"},
    "algorithm_mentions": {"contains": "name/URL of any algorithms"},
    "modularity": {"contains": "code modularized"},
    "code_overall_impression": {"contains": "Overall impression?", "occurrence": 0},
    "development_process": {"contains": "development process defined"},
    "development_status_docs": {"contains": "documents recording the development process"},
    "development_environment": {"contains": "development environment documented"},
    "development_overall_impression": {"contains": "Overall impression?", "occurrence": 1},
}

AI_VALUE_RULES = {
    "funding": "Return one of: unfunded, unclear, or funded (<funding source>).",
    "platforms": "Return a comma-separated set using only Windows, Linux, OS X, Android, other (<details>), or unclear.",
    "performance": "Return yes (<evidence>) or no.",
    "requirements": "Return yes (<evidence>), no, or unclear.",
    "correctness_tools": "Return a comma-separated list from automated testing, assertions used in the code, Sphinx, Doxygen, Javadoc, confluence, other (<details>), or unclear.",
    "unexpected_input": "Return yes, no (<reason>), or unclear.",
    "newline_handling": "Return yes, no (<reason>), n/a, or unclear.",
    "coding_standard": "Return yes (<standard/file>), no, n/a, or unclear.",
    "identifier_quality": "Return yes, no (<reason>), n/a, or unclear.",
    "hard_coded_constants": "Return yes, no, n/a, or unclear.",
    "comment_clarity": "Return yes, no (<reason>), n/a, or unclear.",
    "parameter_order": "Return yes, no (<reason>), n/a, or unclear.",
    "algorithm_mentions": "Return yes (<algorithm/source>), no, n/a, or unclear.",
    "modularity": "Return yes, no (<reason>), n/a, or unclear.",
    "code_overall_impression": "Return only an integer from 1 to 10.",
    "development_process": "Return yes (<process>), no, n/a, or unclear.",
    "development_status_docs": "Return yes (<document/file>), no, or unclear.",
    "development_environment": "Return yes (<evidence>), no, or unclear.",
    "development_overall_impression": "Return only an integer from 1 to 10.",
}

DEEP_AGENT_KEYS = {
    "performance",
    "correctness_tools",
    "unexpected_input",
    "newline_handling",
    "coding_standard",
    "identifier_quality",
    "hard_coded_constants",
    "comment_clarity",
    "parameter_order",
    "algorithm_mentions",
    "modularity",
    "code_overall_impression",
}


@dataclass
class Evidence:
    software: str
    metric: str
    value: str
    source_type: str
    source: str
    evidence: str
    confidence: float = 1.0
    needs_review: bool = False
    repo_url: str = ""

    def as_row(self) -> dict[str, str]:
        return {
            "software": self.software,
            "metric": self.metric,
            "value": self.value,
            "source_type": self.source_type,
            "source": self.source,
            "evidence": self.evidence,
            "confidence": f"{self.confidence:.2f}",
            "needs_review": "yes" if self.needs_review else "no",
            "repo_url": self.repo_url,
        }


@dataclass
class MetricTable:
    fieldnames: list[str]
    rows: list[dict[str, str]]
    software_columns: list[str]

    def row_metric(self, index: int) -> str:
        return (self.rows[index].get("Metric") or "").strip()

    def find_all(self, *, contains: str | None = None, exact: str | None = None) -> list[int]:
        matches: list[int] = []
        needle = contains.lower() if contains else None
        exact_needle = exact.lower() if exact else None
        for index, row in enumerate(self.rows):
            metric = (row.get("Metric") or "").strip()
            metric_lower = metric.lower()
            if exact_needle is not None and metric_lower == exact_needle:
                matches.append(index)
            elif needle is not None and needle in metric_lower:
                matches.append(index)
        return matches

    def find_one(
        self,
        *,
        contains: str | None = None,
        exact: str | None = None,
        occurrence: int = 0,
    ) -> int | None:
        matches = self.find_all(contains=contains, exact=exact)
        if occurrence < len(matches):
            return matches[occurrence]
        return None


@dataclass
class SoftwareContext:
    column: str
    name: str
    website_url: str
    source_urls: str
    primary_repo_url: str
    github_owner: str | None
    github_repo: str | None
    local_repo: Path | None = None
    repo_meta: dict[str, Any] | None = None
    github_languages: dict[str, int] = field(default_factory=dict)
    latest_release: dict[str, Any] | None = None
    latest_tag: dict[str, Any] | None = None
    github_errors: list[str] = field(default_factory=list)
    git_errors: list[str] = field(default_factory=list)
    repo_url_for_evidence: str = ""


class Collector:
    def __init__(
        self,
        table: MetricTable,
        original_rows: list[dict[str, str]],
        env: dict[str, str],
        output_dir: Path,
        repos_dir: Path,
        cache_dir: Path,
        *,
        skip_ai: bool,
        skip_clone: bool,
        force_refresh: bool,
        ai_min_confidence: float,
        git_timeout: int,
        clone_timeout: int,
        deep_agent_review: bool,
        deep_max_files: int,
        deep_batch_files: int,
        deep_file_chars: int,
        deep_timeout: int,
    ) -> None:
        self.table = table
        self.original_rows = original_rows
        self.env = env
        self.output_dir = output_dir
        self.repos_dir = repos_dir
        self.cache_dir = cache_dir
        self.skip_ai = skip_ai
        self.skip_clone = skip_clone
        self.force_refresh = force_refresh
        self.ai_min_confidence = ai_min_confidence
        self.git_timeout = git_timeout
        self.clone_timeout = clone_timeout
        self.deep_agent_review = deep_agent_review
        self.deep_max_files = deep_max_files
        self.deep_batch_files = deep_batch_files
        self.deep_file_chars = deep_file_chars
        self.deep_timeout = deep_timeout
        self.evidence: list[Evidence] = []

    def collect(self, software_columns: list[str]) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.repos_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        source_row = self.table.find_one(contains="Source code URL?")
        name_row = self.table.find_one(contains="Software name?")
        url_row = self.table.find_one(contains="URL?")
        if source_row is None or name_row is None or url_row is None:
            raise RuntimeError("CSV must contain Software name, URL, and Source code URL metric rows.")

        for software in software_columns:
            print(f"[collect] {software}", flush=True)
            source_urls = self.original_rows[source_row].get(software, "").strip()
            context = SoftwareContext(
                column=software,
                name=self.original_rows[name_row].get(software, "").strip() or software.strip(),
                website_url=self.original_rows[url_row].get(software, "").strip(),
                source_urls=source_urls,
                primary_repo_url=first_url(source_urls),
                github_owner=None,
                github_repo=None,
            )
            context.github_owner, context.github_repo = parse_github_repo(context.primary_repo_url)
            context.repo_url_for_evidence = context.primary_repo_url
            self._collect_one(context)
            self._fill_remaining_unclear(context)

    def _collect_one(self, context: SoftwareContext) -> None:
        self._assign_contains(context, "Software name?", context.name, SOURCE_TYPES["input"], "CSV software-name row")
        self._assign_contains(context, "URL?", context.website_url, SOURCE_TYPES["input"], "CSV public URL row")
        self._assign_contains(context, "Source code URL?", context.source_urls, SOURCE_TYPES["input"], "CSV source URL row")

        if context.github_owner and context.github_repo:
            self._collect_github(context)
        else:
            self._mark_github_only_metrics_na(context, "Primary source URL is not a GitHub repository.")

        if context.primary_repo_url and not self.skip_clone:
            self._prepare_repo(context)
        elif self.skip_clone:
            context.git_errors.append("Clone skipped by --skip-clone.")
        else:
            context.git_errors.append("No source repository URL found.")

        if context.local_repo and (context.local_repo / ".git").exists():
            self._collect_git_history(context)
            file_stats = analyze_files(context.local_repo)
            heuristics = analyze_heuristics(context.local_repo, file_stats, context)
            self._collect_file_metrics(context, file_stats, heuristics)
        else:
            self._mark_local_only_metrics_unclear(context, "; ".join(context.git_errors) or "Repository not available locally.")
            file_stats = {}
            heuristics = {}

        deep_review: dict[str, Any] = {}
        if self.deep_agent_review and context.local_repo and (context.local_repo / ".git").exists():
            deep_review = self._collect_deep_agent_review(context, file_stats, heuristics)
            if deep_review:
                heuristics["deep_agent_review"] = {
                    "agent_used": deep_review.get("agent_used", False),
                    "files_reviewed": deep_review.get("files_reviewed", []),
                    "static_scan": deep_review.get("static_scan", {}),
                }

        self._collect_heuristic_metrics(context, heuristics)
        self._collect_ai_metrics(context, file_stats, heuristics, deep_review)
        self._assign_contains(
            context,
            "Additional comments?",
            "Auto-collected; AI-assisted subjective metrics should be reviewed.",
            SOURCE_TYPES["fallback"],
            "Standard note added by collection pipeline.",
            confidence=1.0,
            needs_review=False,
        )

    def _collect_github(self, context: SoftwareContext) -> None:
        owner = context.github_owner or ""
        repo = context.github_repo or ""
        repo_path = f"/repos/{owner}/{repo}"
        repo_meta = self.github_get(repo_path, cache_key=f"repo_{owner}_{repo}")
        if repo_meta is None or repo_meta.get("_error"):
            err = repo_meta.get("_error", "GitHub API failed") if isinstance(repo_meta, dict) else "GitHub API failed"
            context.github_errors.append(str(err))
            self._mark_github_only_metrics_na(context, str(err))
            return

        context.repo_meta = repo_meta
        context.github_languages = self.github_get(f"{repo_path}/languages", cache_key=f"languages_{owner}_{repo}") or {}
        tags = self.github_get(f"{repo_path}/tags", {"per_page": "1"}, cache_key=f"tags_{owner}_{repo}") or []
        releases = self.github_get(f"{repo_path}/releases/latest", cache_key=f"latest_release_{owner}_{repo}") or {}
        if isinstance(tags, list) and tags:
            context.latest_tag = tags[0]
        if isinstance(releases, dict) and not releases.get("_error"):
            context.latest_release = releases

        license_value = map_license(repo_meta.get("license") or {})
        language_value = map_languages(context.github_languages)
        version_value = current_version(context)

        self._assign_contains(context, "License?", license_value, SOURCE_TYPES["github"], f"{repo_path}: license")
        self._assign_contains(context, "Programming language(s)?", language_value, SOURCE_TYPES["github"], f"{repo_path}/languages")
        self._assign_contains(context, "What is the current version number?", version_value, SOURCE_TYPES["github"], "latest release/tag")
        self._assign_contains(context, "Number of stars.", str(repo_meta.get("stargazers_count", "unclear")), SOURCE_TYPES["github"], repo_path)
        self._assign_contains(context, "Number of forks.", str(repo_meta.get("forks_count", "unclear")), SOURCE_TYPES["github"], repo_path)
        self._assign_contains(
            context,
            "Number of people watching this repo.",
            str(repo_meta.get("subscribers_count", "unclear")),
            SOURCE_TYPES["github"],
            f"{repo_path}: subscribers_count",
        )
        self._assign_contains(
            context,
            "What issue tracking tool is employed?",
            "git (GitHub Issues)" if repo_meta.get("has_issues") else "none",
            SOURCE_TYPES["github"],
            f"{repo_path}: has_issues={repo_meta.get('has_issues')}",
        )
        self._assign_contains(context, "Which version control system is in use?", "Github", SOURCE_TYPES["github"], repo_path)

        open_prs = self.github_search_count(f"repo:{owner}/{repo} is:pr is:open", f"open_pr_{owner}_{repo}")
        closed_prs = self.github_search_count(f"repo:{owner}/{repo} is:pr is:closed", f"closed_pr_{owner}_{repo}")
        open_issues = self.github_search_count(f"repo:{owner}/{repo} is:issue is:open", f"open_issue_{owner}_{repo}")
        closed_issues = self.github_search_count(f"repo:{owner}/{repo} is:issue is:closed", f"closed_issue_{owner}_{repo}")

        self._assign_contains(context, "Number of open pull requests.", str_or_unclear(open_prs), SOURCE_TYPES["github"], "GitHub search API")
        self._assign_contains(context, "Number of closed pull requests.", str_or_unclear(closed_prs), SOURCE_TYPES["github"], "GitHub search API")
        if open_issues is None or closed_issues is None or (open_issues + closed_issues == 0):
            issue_pct = "unclear"
            issue_evidence = "GitHub issue counts unavailable or zero."
            needs_review = True
        else:
            issue_pct = f"{closed_issues / (open_issues + closed_issues):.2%}"
            issue_evidence = f"closed={closed_issues}; open={open_issues}"
            needs_review = False
        self._assign_contains(
            context,
            "percentage of identified issues that are closed",
            issue_pct,
            SOURCE_TYPES["github"],
            issue_evidence,
            needs_review=needs_review,
        )

    def _prepare_repo(self, context: SoftwareContext) -> None:
        repo_url = context.primary_repo_url
        if not repo_url:
            return
        target_name = repo_dir_name(context)
        target = self.repos_dir / target_name
        context.local_repo = target
        if not shutil.which("git"):
            context.git_errors.append("git executable not found.")
            return

        if not target.exists():
            result = run_cmd(["git", "clone", repo_url, str(target)], timeout=self.clone_timeout)
            if result.returncode != 0:
                context.git_errors.append(f"git clone failed: {summarize_error(result.stderr)}")
                context.local_repo = None
            return

        if not (target / ".git").exists():
            context.git_errors.append(f"{target} exists but is not a git repository.")
            context.local_repo = None
            return

        run_cmd(["git", "-C", str(target), "remote", "set-url", "origin", repo_url], timeout=self.git_timeout)
        fetch = run_cmd(["git", "-C", str(target), "fetch", "--all", "--tags", "--prune"], timeout=self.clone_timeout)
        if fetch.returncode != 0:
            context.git_errors.append(f"git fetch failed: {summarize_error(fetch.stderr)}")
            return

        default_branch = ""
        if context.repo_meta:
            default_branch = str(context.repo_meta.get("default_branch") or "")
        if default_branch:
            run_cmd(["git", "-C", str(target), "checkout", default_branch], timeout=self.git_timeout)
        pull = run_cmd(["git", "-C", str(target), "pull", "--ff-only"], timeout=self.clone_timeout)
        if pull.returncode != 0:
            context.git_errors.append(f"git pull failed: {summarize_error(pull.stderr)}")

    def _collect_git_history(self, context: SoftwareContext) -> None:
        repo = context.local_repo
        if repo is None:
            return

        developers = git_output(repo, ["log", "--format=%aN <%aE>"], timeout=self.git_timeout)
        if developers.ok:
            unique_developers = len({line.strip().lower() for line in developers.stdout.splitlines() if line.strip()})
            self._assign_contains(context, "Number of developers", str(unique_developers), SOURCE_TYPES["git"], "git log authors")
        else:
            self._assign_contains(context, "Number of developers", "unclear", SOURCE_TYPES["git"], developers.error, needs_review=True)

        last_commit = git_output(repo, ["log", "-1", "--format=%cI"], timeout=self.git_timeout)
        if last_commit.ok and last_commit.stdout.strip():
            self._assign_contains(context, "Last commit date?", iso_date(last_commit.stdout.strip()), SOURCE_TYPES["git"], "git log -1 --format=%cI")
        else:
            self._assign_contains(context, "Last commit date?", fallback_pushed_date(context), SOURCE_TYPES["github"], "GitHub pushed_at fallback", needs_review=True)

        first_commit = git_output(repo, ["log", "--reverse", "--format=%cI"], timeout=self.git_timeout)
        if first_commit.ok and first_commit.stdout.strip():
            first_line = first_commit.stdout.splitlines()[0].strip()
            self._assign_contains(
                context,
                "Initial release date?",
                iso_date(first_line),
                SOURCE_TYPES["git"],
                "First commit date used as automated proxy for initial release date.",
                needs_review=True,
            )

        commit_count = git_output(repo, ["rev-list", "--count", "HEAD"], timeout=self.git_timeout)
        self._assign_contains(
            context,
            "Number of total commits.",
            commit_count.stdout.strip() if commit_count.ok else "unclear",
            SOURCE_TYPES["git"],
            "git rev-list --count HEAD" if commit_count.ok else commit_count.error,
            needs_review=not commit_count.ok,
        )

        added, deleted, numstat_error = git_numstat_totals(repo, timeout=max(self.clone_timeout, self.git_timeout))
        self._assign_contains(
            context,
            "Number of total lines added to text-based files.",
            str_or_unclear(added),
            SOURCE_TYPES["git"],
            "git log --numstat" if numstat_error is None else numstat_error,
            needs_review=numstat_error is not None,
        )
        self._assign_contains(
            context,
            "Number of total lines deleted from text-based files.",
            str_or_unclear(deleted),
            SOURCE_TYPES["git"],
            "git log --numstat" if numstat_error is None else numstat_error,
            needs_review=numstat_error is not None,
        )

        self._assign_contains(
            context,
            "Numbers of commits by year in the last 5 years.",
            format_count_series(git_counts_by_year(repo, timeout=self.git_timeout)),
            SOURCE_TYPES["git"],
            "git log dates grouped by calendar year",
        )
        self._assign_contains(
            context,
            "Numbers of commits by month in the last 12 months.",
            format_count_series(git_counts_by_month(repo, timeout=self.git_timeout)),
            SOURCE_TYPES["git"],
            "git log dates grouped by calendar month",
        )

        if not (context.github_owner and context.github_repo):
            self._assign_contains(context, "Which version control system is in use?", "git", SOURCE_TYPES["git"], "Local git repository")

    def _collect_file_metrics(self, context: SoftwareContext, stats: dict[str, Any], heuristics: dict[str, Any]) -> None:
        if context.local_repo:
            detected_license, license_evidence = detect_license_file(context.local_repo)
            if detected_license != "unclear":
                self._assign_contains(context, "License?", detected_license, SOURCE_TYPES["files"], license_evidence)
        self._assign_all_contains(context, "Number of text-based files.", str(stats.get("text_files", "unclear")), SOURCE_TYPES["files"], "Tracked file scan")
        self._assign_contains(context, "Number of binary files.", str(stats.get("binary_files", "unclear")), SOURCE_TYPES["files"], "Tracked file scan")
        self._assign_all_contains(
            context,
            "Number of total lines in text-based files.",
            str(stats.get("total_text_lines", "unclear")),
            SOURCE_TYPES["files"],
            "Tracked text file line count",
        )
        self._assign_contains(context, "Number of code lines in text-based files.", str(stats.get("code_lines", "unclear")), SOURCE_TYPES["files"], "Code-like tracked files")
        self._assign_contains(context, "Number of comment lines in text-based files.", str(stats.get("comment_lines", "unclear")), SOURCE_TYPES["files"], "Code-like tracked files")
        self._assign_contains(context, "Number of blank lines in text-based files.", str(stats.get("blank_lines", "unclear")), SOURCE_TYPES["files"], "Tracked text files")
        self._assign_contains(context, "What percentage of code is comments?", stats.get("comment_percentage", "unclear"), SOURCE_TYPES["files"], "comment_lines / total_text_lines")
        self._assign_contains(context, "How many code files are there?", str(stats.get("code_files", "unclear")), SOURCE_TYPES["files"], "Tracked file extension scan")

    def _collect_heuristic_metrics(self, context: SoftwareContext, heuristics: dict[str, Any]) -> None:
        assignments = {
            "Are unit tests available?": "unit_tests",
            "Is there evidence of continuous integration?": "ci",
            "Is API documented?": "api_docs",
            "Is there any information on how code is reviewed": "contributing",
            "Are artifacts available?": "artifacts",
            "Is the development environment documented?": "dev_env_docs",
            "Are release notes?": "release_notes",
        }
        for contains, key in assignments.items():
            item = heuristics.get(key)
            if not item:
                continue
            self._assign_contains(
                context,
                contains,
                item["value"],
                SOURCE_TYPES["heuristic"],
                item["evidence"],
                confidence=item.get("confidence", 0.85),
                needs_review=item.get("needs_review", False),
            )

    def _collect_ai_metrics(
        self,
        context: SoftwareContext,
        file_stats: dict[str, Any],
        heuristics: dict[str, Any],
        deep_review: dict[str, Any] | None = None,
    ) -> None:
        ai_results: dict[str, dict[str, Any]] = {}
        if not self.skip_ai:
            ai_results = self.call_ai(context, file_stats, heuristics, deep_review or {})

        if not ai_results:
            ai_results = fallback_ai_like_results(context, heuristics)

        deep_metrics = {}
        if deep_review:
            raw_metrics = deep_review.get("metrics", {})
            if isinstance(raw_metrics, dict):
                deep_metrics = raw_metrics
                ai_results.update(deep_metrics)

        for key, locator in AI_METRIC_KEYS.items():
            row_index = self.table.find_one(
                contains=locator["contains"],
                occurrence=int(locator.get("occurrence", 0)),
            )
            if row_index is None:
                continue
            result = ai_results.get(key) or {
                "value": "unclear",
                "confidence": 0.0,
                "evidence": "No AI result was available for this metric.",
            }
            confidence = safe_float(result.get("confidence"), 0.0)
            value = normalize_ai_metric_value(key, result.get("value", "unclear"), confidence)
            evidence = normalize_cell(result.get("evidence", "No evidence provided."))
            needs_review = confidence < self.ai_min_confidence or value.lower() in {"unclear", "n/a"}
            is_deep = key in deep_metrics
            deep_agent_used = bool((deep_review or {}).get("agent_used"))
            source_type = SOURCE_TYPES["ai"] if not self.skip_ai else SOURCE_TYPES["fallback"]
            source = "DeepSeek API" if not self.skip_ai else "AI skipped; heuristic fallback"
            if is_deep:
                source_type = SOURCE_TYPES["deep"] if deep_agent_used else SOURCE_TYPES["files"]
                source = "DeepSeek deep code review" if deep_agent_used else "deep static repository scan"
            self._assign_row(
                context,
                row_index,
                value,
                source_type,
                source,
                evidence,
                confidence=confidence,
                needs_review=needs_review,
            )

    def call_ai(
        self,
        context: SoftwareContext,
        file_stats: dict[str, Any],
        heuristics: dict[str, Any],
        deep_review: dict[str, Any] | None = None,
    ) -> dict[str, dict[str, Any]]:
        base_url = self.env.get("DEEPSEEK_BASE_URL", "").rstrip("/")
        api_key = self.env.get("DEEPSEEK_API_KEY", "")
        model = self.env.get("DEEPSEEK_MODEL", "")
        if not base_url or not api_key or not model:
            return {}

        cache_key = f"ai_{context.column}_{hash_text(context.primary_repo_url)}"
        cached = read_cache(self.cache_dir, cache_key)
        if cached is not None and not self.force_refresh:
            return cached if isinstance(cached, dict) else {}

        docs_context = collect_document_context(context.local_repo) if context.local_repo else {}
        payload = {
            "model": model,
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are assisting a research data collection task. "
                        "Return only compact JSON. Do not invent facts; use unclear when evidence is weak."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "task": "Fill subjective or semi-automatic software metrics.",
                            "software": context.name,
                            "repo_url": context.primary_repo_url,
                            "expected_keys": list(AI_METRIC_KEYS),
                            "metric_value_rules": AI_VALUE_RULES,
                            "allowed_format": {
                                "each_key": {
                                    "value": "short table cell value",
                                    "confidence": "0.0-1.0",
                                    "evidence": "brief source-based reason",
                                }
                            },
                            "automated_stats": file_stats,
                            "heuristics": heuristics,
                            "deep_agent_review": summarize_deep_review_for_prompt(deep_review or {}),
                            "repo_metadata": redact_repo_meta(context.repo_meta),
                            "document_context": docs_context,
                        },
                        ensure_ascii=False,
                    ),
                },
            ],
        }

        request = urllib.request.Request(
            f"{base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                data = json.loads(response.read().decode("utf-8"))
            content = data["choices"][0]["message"]["content"]
            parsed = json.loads(extract_json_object(content))
            normalized = normalize_ai_response(parsed)
            write_cache(self.cache_dir, cache_key, normalized)
            return normalized
        except Exception as exc:  # noqa: BLE001 - keep batch runs alive.
            write_cache(self.cache_dir, f"{cache_key}_error", {"error": str(exc)})
            return {}

    def _collect_deep_agent_review(
        self,
        context: SoftwareContext,
        file_stats: dict[str, Any],
        heuristics: dict[str, Any],
    ) -> dict[str, Any]:
        if context.local_repo is None:
            return {}

        head = git_output(context.local_repo, ["rev-parse", "HEAD"], timeout=self.git_timeout)
        head_sha = head.stdout.strip() if head.ok else hash_text(context.primary_repo_url)[:12]
        cache_key = (
            f"deep_agent_{context.column}_{head_sha}_"
            f"{self.deep_max_files}_{self.deep_batch_files}_{self.deep_file_chars}"
        )
        cached = read_cache(self.cache_dir, cache_key)
        if cached is not None and not self.force_refresh:
            return cached if isinstance(cached, dict) else {}

        static_scan = deep_static_code_scan(context.local_repo)
        review_files = select_deep_review_files(context.local_repo, static_scan, self.deep_max_files, self.deep_file_chars)
        metrics = deep_static_fallback_results(static_scan, heuristics)
        agent_used = False
        batch_results: list[dict[str, dict[str, Any]]] = []

        if not self.skip_ai and review_files:
            for batch_index, batch in enumerate(chunks(review_files, max(1, self.deep_batch_files)), start=1):
                batch_result = self.call_deep_review_batch(
                    context,
                    batch,
                    static_scan,
                    file_stats,
                    heuristics,
                    batch_index,
                    head_sha,
                )
                if batch_result:
                    batch_results.append(batch_result)
                    agent_used = True
            if batch_results:
                metrics = merge_deep_agent_results(metrics, batch_results)

        result = {
            "agent_used": agent_used,
            "head_sha": head_sha,
            "files_reviewed": [item["path"] for item in review_files],
            "static_scan": static_scan,
            "metrics": metrics,
        }
        write_cache(self.cache_dir, cache_key, result)
        return result

    def call_deep_review_batch(
        self,
        context: SoftwareContext,
        batch: list[dict[str, Any]],
        static_scan: dict[str, Any],
        file_stats: dict[str, Any],
        heuristics: dict[str, Any],
        batch_index: int,
        head_sha: str,
    ) -> dict[str, dict[str, Any]]:
        base_url = self.env.get("DEEPSEEK_BASE_URL", "").rstrip("/")
        api_key = self.env.get("DEEPSEEK_API_KEY", "")
        model = self.env.get("DEEPSEEK_MODEL", "")
        if not base_url or not api_key or not model:
            return {}

        batch_hash = hash_text(json.dumps(batch, ensure_ascii=False)[:20000])
        cache_key = f"deep_batch_{context.column}_{head_sha}_{batch_index}_{batch_hash}"
        cached = read_cache(self.cache_dir, cache_key)
        if cached is not None and not self.force_refresh:
            return cached if isinstance(cached, dict) else {}

        payload = {
            "model": model,
            "temperature": 0.05,
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a careful code-review agent for research software metrics. "
                        "Use only the provided static scan and code excerpts. "
                        "Return compact JSON. If evidence is insufficient, return unclear with low confidence."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "task": "Deeply review this batch of repository code excerpts for code-quality metrics.",
                            "software": context.name,
                            "repo_url": context.primary_repo_url,
                            "target_metric_keys": sorted(DEEP_AGENT_KEYS),
                            "metric_value_rules": {key: AI_VALUE_RULES[key] for key in sorted(DEEP_AGENT_KEYS)},
                            "required_json_shape": {
                                "metrics": {
                                    "metric_key": {
                                        "value": "short table cell value following the rule",
                                        "confidence": "0.0-1.0",
                                        "evidence": "cite file paths and concrete observations",
                                    }
                                }
                            },
                            "automated_stats": file_stats,
                            "heuristics": heuristics,
                            "static_scan_summary": static_scan,
                            "code_excerpts": batch,
                        },
                        ensure_ascii=False,
                    ),
                },
            ],
        }

        request = urllib.request.Request(
            f"{base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.deep_timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
            content = data["choices"][0]["message"]["content"]
            parsed = json.loads(extract_json_object(content))
            metrics = parsed.get("metrics", parsed)
            normalized = normalize_deep_agent_metrics(metrics)
            write_cache(self.cache_dir, cache_key, normalized)
            return normalized
        except Exception as exc:  # noqa: BLE001
            write_cache(self.cache_dir, f"{cache_key}_error", {"error": str(exc)})
            return {}

    def github_get(self, path: str, params: dict[str, str] | None = None, *, cache_key: str) -> Any:
        cached = read_cache(self.cache_dir, cache_key)
        if cached is not None and not self.force_refresh:
            return cached

        token = self.env.get("GITHUB_TOKEN", "")
        query = f"?{urllib.parse.urlencode(params)}" if params else ""
        request = urllib.request.Request(
            f"https://api.github.com{path}{query}",
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                **({"Authorization": f"Bearer {token}"} if token else {}),
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                data = json.loads(response.read().decode("utf-8"))
            write_cache(self.cache_dir, cache_key, data)
            return data
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")[:500]
            data = {"_error": f"HTTP {exc.code}: {body}"}
            write_cache(self.cache_dir, cache_key, data)
            return data
        except Exception as exc:  # noqa: BLE001
            data = {"_error": str(exc)}
            write_cache(self.cache_dir, cache_key, data)
            return data

    def github_search_count(self, query: str, cache_key: str) -> int | None:
        data = self.github_get("/search/issues", {"q": query, "per_page": "1"}, cache_key=cache_key)
        if isinstance(data, dict) and "total_count" in data:
            return int(data["total_count"])
        return None

    def _mark_github_only_metrics_na(self, context: SoftwareContext, reason: str) -> None:
        for contains in [
            "Number of stars.",
            "Number of forks.",
            "Number of people watching this repo.",
            "Number of open pull requests.",
            "Number of closed pull requests.",
            "percentage of identified issues that are closed",
        ]:
            self._assign_contains(context, contains, "n/a", SOURCE_TYPES["github"], reason, needs_review=False)
        self._assign_contains(context, "What issue tracking tool is employed?", "unclear", SOURCE_TYPES["fallback"], reason, needs_review=True)
        if context.primary_repo_url:
            self._assign_contains(context, "Which version control system is in use?", "git", SOURCE_TYPES["fallback"], reason, needs_review=True)

    def _mark_local_only_metrics_unclear(self, context: SoftwareContext, reason: str) -> None:
        for contains in [
            "Number of developers",
            "Last commit date?",
            "Initial release date?",
            "Number of total commits.",
            "Number of total lines added",
            "Number of total lines deleted",
            "Numbers of commits by year",
            "Numbers of commits by month",
            "Number of binary files.",
            "Number of code lines",
            "Number of comment lines",
            "Number of blank lines",
            "What percentage of code is comments?",
            "How many code files",
        ]:
            self._assign_contains(context, contains, "unclear", SOURCE_TYPES["git"], reason, needs_review=True)
        self._assign_all_contains(context, "Number of text-based files.", "unclear", SOURCE_TYPES["files"], reason, needs_review=True)
        self._assign_all_contains(context, "Number of total lines in text-based files.", "unclear", SOURCE_TYPES["files"], reason, needs_review=True)

    def _fill_remaining_unclear(self, context: SoftwareContext) -> None:
        for row_index, row in enumerate(self.table.rows):
            metric = (row.get("Metric") or "").strip()
            if not metric:
                continue
            if not (row.get(context.column) or "").strip():
                self._assign_row(
                    context,
                    row_index,
                    "unclear",
                    SOURCE_TYPES["fallback"],
                    "collector fallback",
                    "No automatic collector produced a value for this metric.",
                    confidence=0.0,
                    needs_review=True,
                )

    def _assign_contains(
        self,
        context: SoftwareContext,
        contains: str,
        value: Any,
        source_type: str,
        evidence: str,
        *,
        confidence: float = 1.0,
        needs_review: bool = False,
        occurrence: int = 0,
    ) -> None:
        row_index = self.table.find_one(contains=contains, occurrence=occurrence)
        if row_index is not None:
            self._assign_row(context, row_index, value, source_type, source_type, evidence, confidence=confidence, needs_review=needs_review)

    def _assign_all_contains(
        self,
        context: SoftwareContext,
        contains: str,
        value: Any,
        source_type: str,
        evidence: str,
        *,
        confidence: float = 1.0,
        needs_review: bool = False,
    ) -> None:
        for row_index in self.table.find_all(contains=contains):
            self._assign_row(context, row_index, value, source_type, source_type, evidence, confidence=confidence, needs_review=needs_review)

    def _assign_row(
        self,
        context: SoftwareContext,
        row_index: int,
        value: Any,
        source_type: str,
        source: str,
        evidence: str,
        *,
        confidence: float = 1.0,
        needs_review: bool = False,
    ) -> None:
        metric = self.table.row_metric(row_index)
        cell_value = normalize_cell(value)
        self.table.rows[row_index][context.column] = cell_value
        self.evidence.append(
            Evidence(
                software=context.column,
                metric=metric,
                value=cell_value,
                source_type=source_type,
                source=source,
                evidence=normalize_cell(evidence),
                confidence=confidence,
                needs_review=needs_review,
                repo_url=context.repo_url_for_evidence,
            )
        )


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass
class GitOutput:
    ok: bool
    stdout: str = ""
    error: str = ""


def load_env(path: Path) -> dict[str, str]:
    env = dict(os.environ)
    if not path.exists():
        return env
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def load_table(input_path: Path) -> MetricTable:
    with input_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = list(reader.fieldnames or [])
        rows = [{key: (value or "") for key, value in row.items()} for row in reader]
    if not fieldnames or fieldnames[0] != "Metric":
        raise RuntimeError("Expected first CSV column to be Metric.")
    return MetricTable(fieldnames=fieldnames, rows=rows, software_columns=fieldnames[1:])


def save_csv(path: Path, table: MetricTable) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=table.fieldnames)
        writer.writeheader()
        writer.writerows(table.rows)


def save_evidence(path: Path, evidence: list[Evidence]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["software", "metric", "value", "source_type", "source", "evidence", "confidence", "needs_review", "repo_url"]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for item in evidence:
            writer.writerow(item.as_row())


def save_xlsx(path: Path, table: MetricTable) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    values = [table.fieldnames] + [[row.get(field, "") for field in table.fieldnames] for row in table.rows]
    sheet_xml = build_sheet_xml(values)
    content_types = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
</Types>"""
    rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"""
    workbook = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets><sheet name="metrics" sheetId="1" r:id="rId1"/></sheets>
</workbook>"""
    workbook_rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>"""
    styles = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="1"><font><sz val="11"/><name val="Calibri"/></font></fonts>
  <fills count="1"><fill><patternFill patternType="none"/></fill></fills>
  <borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/></cellXfs>
  <cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>"""
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", rels)
        archive.writestr("xl/workbook.xml", workbook)
        archive.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        archive.writestr("xl/styles.xml", styles)
        archive.writestr("xl/worksheets/sheet1.xml", sheet_xml)


def build_sheet_xml(values: list[list[str]]) -> str:
    rows_xml: list[str] = []
    for row_index, row in enumerate(values, start=1):
        cells: list[str] = []
        for col_index, value in enumerate(row, start=1):
            if value == "":
                continue
            ref = f"{column_letters(col_index)}{row_index}"
            escaped = escape(str(value), {'"': "&quot;"})
            cells.append(f'<c r="{ref}" t="inlineStr"><is><t xml:space="preserve">{escaped}</t></is></c>')
        rows_xml.append(f'<row r="{row_index}">{"".join(cells)}</row>')
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>'
        '<sheetData>'
        + "".join(rows_xml)
        + "</sheetData></worksheet>"
    )


def column_letters(index: int) -> str:
    letters = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        letters = chr(65 + remainder) + letters
    return letters


def first_url(value: str) -> str:
    match = re.search(r"https?://[^\s,]+", value or "")
    if not match:
        return ""
    return match.group(0).rstrip(").;")


def parse_github_repo(url: str) -> tuple[str | None, str | None]:
    if not url:
        return None, None
    parsed = urllib.parse.urlparse(url)
    if parsed.netloc.lower() not in {"github.com", "www.github.com"}:
        return None, None
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) < 2:
        return None, None
    owner = parts[0]
    repo = re.sub(r"\.git$", "", parts[1])
    return owner, repo


def repo_dir_name(context: SoftwareContext) -> str:
    if context.github_owner and context.github_repo:
        base = f"{context.github_owner}__{context.github_repo}"
    else:
        base = f"{context.column}__{hash_text(context.primary_repo_url)[:10]}"
    return sanitize_path_name(base)


def sanitize_path_name(value: str) -> str:
    value = re.sub(r'[<>:"/\\|?*]+', "_", value)
    value = re.sub(r"\s+", "_", value.strip())
    return value[:120] or "repo"


def run_cmd(args: list[str], *, timeout: int) -> CommandResult:
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        return CommandResult(proc.returncode, proc.stdout, proc.stderr)
    except subprocess.TimeoutExpired as exc:
        return CommandResult(124, exc.stdout or "", f"Command timed out after {timeout}s")
    except Exception as exc:  # noqa: BLE001
        return CommandResult(1, "", str(exc))


def git_output(repo: Path, args: list[str], *, timeout: int) -> GitOutput:
    result = run_cmd(["git", "-C", str(repo), *args], timeout=timeout)
    if result.returncode == 0:
        return GitOutput(True, result.stdout, "")
    return GitOutput(False, "", summarize_error(result.stderr))


def git_numstat_totals(repo: Path, *, timeout: int) -> tuple[int | None, int | None, str | None]:
    args = ["git", "-C", str(repo), "log", "--numstat", "--pretty=tformat:"]
    started = time.time()
    added = 0
    deleted = 0
    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            if time.time() - started > timeout:
                proc.kill()
                return None, None, f"git numstat timed out after {timeout}s"
            parts = line.strip().split("\t")
            if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
                added += int(parts[0])
                deleted += int(parts[1])
        stderr = proc.stderr.read() if proc.stderr else ""
        returncode = proc.wait(timeout=5)
        if returncode != 0:
            return None, None, summarize_error(stderr)
        return added, deleted, None
    except Exception as exc:  # noqa: BLE001
        return None, None, str(exc)


def git_counts_by_year(repo: Path, *, timeout: int) -> dict[str, int]:
    start_year = TODAY.year - 4
    result = git_output(repo, ["log", f"--since={start_year}-01-01", "--date=format:%Y", "--format=%cd"], timeout=timeout)
    years = [str(year) for year in range(start_year, TODAY.year + 1)]
    counts = {year: 0 for year in years}
    if result.ok:
        for line in result.stdout.splitlines():
            if line.strip() in counts:
                counts[line.strip()] += 1
    return counts


def git_counts_by_month(repo: Path, *, timeout: int) -> dict[str, int]:
    months = last_n_months(TODAY, 12)
    since = f"{months[0]}-01"
    result = git_output(repo, ["log", f"--since={since}", "--date=format:%Y-%m", "--format=%cd"], timeout=timeout)
    counts = {month: 0 for month in months}
    if result.ok:
        for line in result.stdout.splitlines():
            if line.strip() in counts:
                counts[line.strip()] += 1
    return counts


def last_n_months(today: dt.date, n: int) -> list[str]:
    months: list[str] = []
    year = today.year
    month = today.month
    for _ in range(n):
        months.append(f"{year:04d}-{month:02d}")
        month -= 1
        if month == 0:
            month = 12
            year -= 1
    return list(reversed(months))


def format_count_series(counts: dict[str, int]) -> str:
    return "; ".join(f"{key}: {value}" for key, value in counts.items())


def tracked_files(repo: Path) -> list[Path]:
    result = run_cmd(["git", "-C", str(repo), "ls-files", "-z"], timeout=120)
    if result.returncode == 0:
        return [repo / item for item in result.stdout.split("\0") if item]
    files: list[Path] = []
    for path in repo.rglob("*"):
        if path.is_dir() and path.name in SKIP_DIRS:
            continue
        if path.is_file() and not any(part in SKIP_DIRS for part in path.relative_to(repo).parts):
            files.append(path)
    return files


def analyze_files(repo: Path) -> dict[str, Any]:
    files = tracked_files(repo)
    stats = {
        "text_files": 0,
        "binary_files": 0,
        "code_files": 0,
        "total_text_lines": 0,
        "code_lines": 0,
        "comment_lines": 0,
        "blank_lines": 0,
        "artifact_categories": set(),
        "sample_files": [],
    }
    for path in files:
        if not path.exists() or not path.is_file():
            continue
        rel = str(path.relative_to(repo)).replace("\\", "/")
        ext = path.suffix.lower()
        if is_binary_file(path):
            stats["binary_files"] += 1
            classify_artifact(ext, rel, stats["artifact_categories"])
            continue
        stats["text_files"] += 1
        if len(stats["sample_files"]) < 20:
            stats["sample_files"].append(rel)
        text = read_text_lossy(path)
        lines = text.splitlines()
        stats["total_text_lines"] += len(lines)
        stats["blank_lines"] += sum(1 for line in lines if not line.strip())
        if ext in CODE_EXTS or path.name.lower() in {"cmakelists.txt", "dockerfile", "makefile"}:
            stats["code_files"] += 1
            code, comments = classify_code_lines(lines)
            stats["code_lines"] += code
            stats["comment_lines"] += comments
        else:
            classify_artifact(ext, rel, stats["artifact_categories"])
    denominator = stats["total_text_lines"] or 0
    stats["comment_percentage"] = f"{stats['comment_lines'] / denominator:.2%}" if denominator else "unclear"
    stats["artifact_categories"] = sorted(stats["artifact_categories"])
    return stats


def is_binary_file(path: Path) -> bool:
    if path.suffix.lower() in BINARY_HINT_EXTS:
        return True
    try:
        data = path.read_bytes()[:8192]
    except OSError:
        return True
    if b"\0" in data:
        return True
    try:
        data.decode("utf-8")
        return False
    except UnicodeDecodeError:
        try:
            data.decode("utf-16")
            return False
        except UnicodeDecodeError:
            return True


def read_text_lossy(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def classify_code_lines(lines: list[str]) -> tuple[int, int]:
    code = 0
    comments = 0
    in_block = False
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if in_block:
            comments += 1
            if "*/" in stripped or "-->" in stripped:
                in_block = False
            continue
        if stripped.startswith(("/*", "<!--")):
            comments += 1
            if "*/" not in stripped and "-->" not in stripped:
                in_block = True
            continue
        if stripped.startswith(("//", "#", "*", "--", "%", ";", "REM ", "rem ")):
            comments += 1
        else:
            code += 1
    return code, comments


def classify_artifact(ext: str, rel: str, categories: set[str]) -> None:
    lower = rel.lower()
    if ext in {".md", ".rst", ".txt", ".pdf"} or "doc" in lower:
        categories.add("documentation")
    elif ext in {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico"}:
        categories.add("images")
    elif ext in {".csv", ".json", ".yaml", ".yml", ".xml", ".dat", ".obj", ".stl", ".urdf", ".sdf"}:
        categories.add("data/configuration")
    elif ext in {".ipynb"}:
        categories.add("notebooks")
    elif ext in {".cmake", ".toml", ".ini", ".cfg", ".conf"}:
        categories.add("configuration")
    elif ext and ext not in CODE_EXTS:
        categories.add(f"other {ext}")


def analyze_heuristics(repo: Path, file_stats: dict[str, Any], context: SoftwareContext) -> dict[str, Any]:
    paths = [path.relative_to(repo).as_posix() for path in tracked_files(repo) if path.exists()]
    lower_paths = [path.lower() for path in paths]

    def matches(patterns: list[str]) -> list[str]:
        found = []
        for original, lower in zip(paths, lower_paths):
            if any(re.search(pattern, lower) for pattern in patterns):
                found.append(original)
        return found[:12]

    unit_tests = matches([r"(^|/)tests?(/|$)", r"(^|/)test[_-].*\.", r"[_-]test\.", r"(^|/)gtest(/|$)", r"(^|/)pytest"])
    ci = matches([r"^\.github/workflows/", r"^\.travis\.yml$", r"^appveyor\.yml$", r"^azure-pipelines", r"jenkinsfile", r"^\.circleci/"])
    api_docs = matches([r"(^|/)docs?/(api|reference)", r"doxygen", r"conf\.py$", r"mkdocs\.ya?ml$", r"javadocs?"])
    contributing = matches([r"contributing", r"codeowners", r"pull_request_template", r"code_of_conduct"])
    dev_env = matches([r"dockerfile", r"environment\.ya?ml", r"requirements\.txt", r"pyproject\.toml", r"package\.xml", r"cmakelists\.txt", r"(^|/)install"])
    releases = matches([r"changelog", r"release", r"news\.md", r"history"])
    artifacts = file_stats.get("artifact_categories", [])

    heuristics = {
        "unit_tests": yes_no_item(unit_tests, "yes", "no", "test-related files/directories"),
        "ci": yes_no_item(ci, "yes", "no", "CI configuration files"),
        "api_docs": yes_no_item(api_docs, "yes", "no", "API documentation indicators"),
        "contributing": yes_no_item(contributing, "yes", "no", "contribution/code review files"),
        "dev_env_docs": yes_no_item(dev_env, "yes", "no", "development environment files"),
        "release_notes": yes_no_item(releases, "yes", "no", "release note files"),
        "artifacts": {
            "value": f"yes ({', '.join(artifacts[:8])})" if artifacts else "no",
            "evidence": f"artifact categories from tracked files: {', '.join(artifacts[:12])}" if artifacts else "No non-code artifact categories detected.",
            "confidence": 0.80 if artifacts else 0.65,
            "needs_review": not bool(artifacts),
        },
        "path_counts": {
            "unit_tests": len(unit_tests),
            "ci": len(ci),
            "api_docs": len(api_docs),
            "contributing": len(contributing),
            "dev_env": len(dev_env),
            "release_notes": len(releases),
        },
    }
    if context.repo_meta and context.repo_meta.get("has_wiki"):
        heuristics["api_docs"]["evidence"] += "; GitHub wiki is enabled"
    return heuristics


def detect_license_file(repo: Path) -> tuple[str, str]:
    candidates: list[Path] = []
    for pattern in ["LICENSE*", "COPYING*", "COPYRIGHT*", "NOTICE*"]:
        candidates.extend(path for path in repo.glob(pattern) if path.is_file())
    for path in candidates[:10]:
        text = read_text_lossy(path)[:50000]
        lower = text.lower()
        value = "unclear"
        if "mit license" in lower:
            value = "mit"
        elif "apache license" in lower or "apache-2.0" in lower:
            value = "other (Apache-2.0)"
        elif "gnu lesser general public license" in lower or "lgpl" in lower:
            value = "other (LGPL)"
        elif "gnu general public license" in lower or re.search(r"\bgpl\b", lower):
            value = "GNU GPL"
        elif "zlib" in lower:
            value = "other (zlib License)"
        elif "bsd" in lower or "redistribution and use in source and binary forms" in lower:
            value = "bsd"
        if value != "unclear":
            return value, f"Detected from {path.relative_to(repo).as_posix()}"
    return "unclear", "No recognizable LICENSE/COPYING file found."


def deep_static_code_scan(repo: Path) -> dict[str, Any]:
    files = [path for path in tracked_files(repo) if path.exists() and path.is_file()]
    scan: dict[str, Any] = {
        "code_files_scanned": 0,
        "code_lines_scanned": 0,
        "reviewable_code_files": 0,
        "generated_or_vendor_files_skipped": 0,
        "top_level_code_dirs": {},
        "languages_by_extension": {},
        "hardcoded_numeric_sample_count": 0,
        "hardcoded_numeric_samples": [],
        "input_validation_sample_count": 0,
        "input_validation_samples": [],
        "newline_handling_sample_count": 0,
        "newline_handling_samples": [],
        "algorithm_sample_count": 0,
        "algorithm_samples": [],
        "performance_sample_count": 0,
        "performance_samples": [],
        "coding_standard_files": [],
        "mixed_indentation_files": [],
        "function_signature_conflict_count": 0,
        "function_signature_conflict_samples": [],
        "largest_code_files": [],
    }
    signatures: dict[str, set[str]] = {}

    for path in files:
        rel = path.relative_to(repo).as_posix()
        ext = path.suffix.lower()
        name = path.name.lower()
        if not (ext in CODE_EXTS or name in {"cmakelists.txt", "dockerfile", "makefile"}):
            if re.search(r"(^|/)(\.clang-format|\.editorconfig|astyle|uncrustify|clang-tidy)", rel.lower()):
                append_limited(scan["coding_standard_files"], rel, 20)
            continue
        scan["code_files_scanned"] += 1
        scan["languages_by_extension"][ext or name] = scan["languages_by_extension"].get(ext or name, 0) + 1
        top_dir = rel.split("/", 1)[0] if "/" in rel else "."
        scan["top_level_code_dirs"][top_dir] = scan["top_level_code_dirs"].get(top_dir, 0) + 1

        if looks_generated_or_vendor(rel):
            scan["generated_or_vendor_files_skipped"] += 1
            continue
        if is_binary_file(path):
            continue

        text = read_text_lossy(path)
        lines = text.splitlines()
        scan["reviewable_code_files"] += 1
        scan["code_lines_scanned"] += len(lines)
        append_limited(scan["largest_code_files"], {"path": rel, "lines": len(lines)}, 20, key=lambda item: item["lines"])

        if file_has_mixed_indentation(lines):
            append_limited(scan["mixed_indentation_files"], rel, 20)

        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            lower = stripped.lower()
            if numeric_literal_signal(stripped):
                scan["hardcoded_numeric_sample_count"] += 1
                append_limited(scan["hardcoded_numeric_samples"], sample_line(rel, line_no, stripped), 20)
            if re.search(r"\b(try|catch|except|throw|raise|assert|invalid|error|warning|errno|nullptr|null|none|empty|fail)\b", lower):
                scan["input_validation_sample_count"] += 1
                append_limited(scan["input_validation_samples"], sample_line(rel, line_no, stripped), 20)
            if re.search(r"(getline|readline|splitlines|crlf|newline|line ending|\\r\\n|\\n)", lower):
                scan["newline_handling_sample_count"] += 1
                append_limited(scan["newline_handling_samples"], sample_line(rel, line_no, stripped), 20)
            if re.search(r"\b(algorithm|planner|solver|rrt|astar|dijkstra|kalman|newton|euler|runge|gradient|collision|optimization|inverse kinematics|dynamics)\b", lower):
                scan["algorithm_sample_count"] += 1
                append_limited(scan["algorithm_samples"], sample_line(rel, line_no, stripped), 20)
            if re.search(r"\b(performance|benchmark|optimi[sz]e|throughput|latency|fast|cache|parallel|simd|profile|profiling)\b", lower):
                scan["performance_sample_count"] += 1
                append_limited(scan["performance_samples"], sample_line(rel, line_no, stripped), 20)

        for func_name, params in extract_function_signatures(lines, ext):
            signatures.setdefault(func_name, set()).add(params)

    conflicts = []
    for func_name, variants in signatures.items():
        if len(variants) > 1 and len(func_name) > 2:
            conflicts.append({"function": func_name, "signature_variants": sorted(variants)[:5]})
    scan["function_signature_conflict_count"] = len(conflicts)
    scan["function_signature_conflict_samples"] = conflicts[:20]
    scan["top_level_code_dirs"] = dict(sorted(scan["top_level_code_dirs"].items(), key=lambda item: item[1], reverse=True)[:20])
    scan["languages_by_extension"] = dict(sorted(scan["languages_by_extension"].items(), key=lambda item: item[1], reverse=True)[:20])
    scan["largest_code_files"] = sorted(scan["largest_code_files"], key=lambda item: item["lines"], reverse=True)[:20]
    return scan


def select_deep_review_files(repo: Path, static_scan: dict[str, Any], max_files: int, max_chars: int) -> list[dict[str, Any]]:
    candidates: list[tuple[int, Path]] = []
    signal_paths = set()
    for key in [
        "hardcoded_numeric_samples",
        "input_validation_samples",
        "newline_handling_samples",
        "algorithm_samples",
        "performance_samples",
        "mixed_indentation_files",
        "coding_standard_files",
    ]:
        for item in static_scan.get(key, []):
            if isinstance(item, dict) and item.get("path"):
                signal_paths.add(item["path"])
            elif isinstance(item, str):
                signal_paths.add(item)

    for path in tracked_files(repo):
        if not path.exists() or not path.is_file() or is_binary_file(path):
            continue
        rel = path.relative_to(repo).as_posix()
        ext = path.suffix.lower()
        name = path.name.lower()
        if not (ext in CODE_EXTS or name in {"cmakelists.txt", "dockerfile", "makefile"}):
            continue
        if looks_generated_or_vendor(rel):
            continue
        score = 0
        lower = rel.lower()
        if rel in signal_paths:
            score += 50
        if any(part in lower for part in ["/src/", "/include/", "/lib/", "/core/", "/ompl/", "/newton", "/source/"]):
            score += 25
        if any(part in lower for part in ["/test", "/tests/"]):
            score += 8
        if ext in {".cpp", ".cc", ".cxx", ".c", ".h", ".hpp", ".py", ".java"}:
            score += 15
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        if 1_000 <= size <= 120_000:
            score += 10
        elif size > 750_000:
            score -= 30
        candidates.append((score, path))

    selected: list[Path] = []
    seen_dirs: set[str] = set()
    seen_exts: set[str] = set()
    for _score, path in sorted(candidates, key=lambda item: item[0], reverse=True):
        rel = path.relative_to(repo).as_posix()
        top = rel.split("/", 1)[0] if "/" in rel else "."
        ext = path.suffix.lower()
        if len(selected) < max_files // 2 or top not in seen_dirs or ext not in seen_exts:
            selected.append(path)
            seen_dirs.add(top)
            seen_exts.add(ext)
        if len(selected) >= max_files:
            break

    review_files = []
    for path in selected:
        rel = path.relative_to(repo).as_posix()
        review_files.append(
            {
                "path": rel,
                "extension": path.suffix.lower(),
                "excerpt": build_code_excerpt(path, max_chars),
            }
        )
    return review_files


def deep_static_fallback_results(static_scan: dict[str, Any], heuristics: dict[str, Any]) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    input_samples = static_scan.get("input_validation_samples", [])
    newline_samples = static_scan.get("newline_handling_samples", [])
    algorithm_samples = static_scan.get("algorithm_samples", [])
    performance_samples = static_scan.get("performance_samples", [])
    hardcoded_samples = static_scan.get("hardcoded_numeric_samples", [])
    style_files = static_scan.get("coding_standard_files", [])
    mixed_indent = static_scan.get("mixed_indentation_files", [])
    conflicts = static_scan.get("function_signature_conflict_samples", [])
    code_files = int(static_scan.get("reviewable_code_files") or 0)
    top_dirs = static_scan.get("top_level_code_dirs", {})

    results["performance"] = yes_unclear_from_samples(performance_samples, "performance-related code references")
    results["unexpected_input"] = yes_unclear_from_samples(input_samples, "input validation/error handling code references")
    results["newline_handling"] = yes_unclear_from_samples(newline_samples, "newline or line-reading code references")
    results["algorithm_mentions"] = yes_unclear_from_samples(algorithm_samples, "algorithm-related code references")
    results["coding_standard"] = (
        {"value": f"yes ({', '.join(style_files[:5])})", "confidence": 0.70, "evidence": f"Found coding style files: {', '.join(style_files[:10])}"}
        if style_files
        else {"value": "unclear", "confidence": 0.35, "evidence": "No coding standard file found in static scan."}
    )
    results["hard_coded_constants"] = (
        {
            "value": f"yes ({len(hardcoded_samples)} sampled numeric literals; see evidence)",
            "confidence": 0.55,
            "evidence": "Static scan found non-trivial numeric literals: " + join_sample_lines(hardcoded_samples[:5]),
        }
        if hardcoded_samples
        else {"value": "unclear", "confidence": 0.35, "evidence": "No hard-coded numeric literal samples found by static scan."}
    )
    results["parameter_order"] = (
        {
            "value": f"no ({len(conflicts)} repeated function names have different parameter signatures)",
            "confidence": 0.50,
            "evidence": "Static signature scan samples: " + json.dumps(conflicts[:5], ensure_ascii=False),
        }
        if conflicts
        else {"value": "unclear", "confidence": 0.35, "evidence": "Static scan did not find repeated function signature conflicts, but this metric needs deeper API review."}
    )
    results["identifier_quality"] = {
        "value": "unclear",
        "confidence": 0.35,
        "evidence": "Identifier quality requires semantic code review; static scan alone is not enough.",
    }
    results["comment_clarity"] = {
        "value": "unclear" if not mixed_indent else f"no ({len(mixed_indent)} files show mixed indentation; comment clarity still needs review)",
        "confidence": 0.35 if not mixed_indent else 0.45,
        "evidence": "Static scan evidence: " + (", ".join(mixed_indent[:10]) if mixed_indent else "no direct comment clarity evidence."),
    }
    results["modularity"] = (
        {
            "value": f"yes ({len(top_dirs)} top-level code areas; {code_files} reviewable code files)",
            "confidence": 0.60,
            "evidence": f"Static scan top-level code directories: {top_dirs}",
        }
        if len(top_dirs) >= 3 and code_files >= 20
        else {"value": "unclear", "confidence": 0.35, "evidence": f"Static scan found {code_files} reviewable code files across {len(top_dirs)} top-level areas."}
    )
    correctness_bits = []
    for key in ["unit_tests", "ci", "api_docs"]:
        value = heuristics.get(key, {}).get("value", "")
        if value.startswith("yes"):
            correctness_bits.append(value)
    results["correctness_tools"] = (
        {
            "value": "automated testing, CI, documentation indicators",
            "confidence": 0.65,
            "evidence": "Static/heuristic evidence: " + " | ".join(correctness_bits),
        }
        if correctness_bits
        else {"value": "unclear", "confidence": 0.35, "evidence": "No strong correctness-tool evidence found by deep static scan."}
    )
    results["code_overall_impression"] = {
        "value": "unclear",
        "confidence": 0.30,
        "evidence": "Overall impression is reserved for AI or human review.",
    }
    return results


def merge_deep_agent_results(
    fallback: dict[str, dict[str, Any]],
    batch_results: list[dict[str, dict[str, Any]]],
) -> dict[str, dict[str, Any]]:
    merged = dict(fallback)
    numeric_scores: list[int] = []
    numeric_evidence: list[str] = []
    for result in batch_results:
        for key, item in result.items():
            if key not in DEEP_AGENT_KEYS:
                continue
            confidence = safe_float(item.get("confidence"), 0.0)
            value = normalize_ai_metric_value(key, item.get("value", "unclear"), confidence)
            evidence = normalize_cell(item.get("evidence", "No evidence provided."))
            if key == "code_overall_impression":
                if value.isdigit():
                    numeric_scores.append(int(value))
                    numeric_evidence.append(evidence)
                continue
            current = merged.get(key, {"confidence": 0.0, "value": "unclear", "evidence": ""})
            current_conf = safe_float(current.get("confidence"), 0.0)
            current_value = normalize_cell(current.get("value", "unclear")).lower()
            if confidence > current_conf or (current_value == "unclear" and value.lower() != "unclear"):
                merged[key] = {"value": value, "confidence": confidence, "evidence": evidence}
            elif evidence and evidence not in normalize_cell(current.get("evidence", "")):
                current["evidence"] = shorten_cell(f"{current.get('evidence', '')}; {evidence}", 350)
                merged[key] = current

    if numeric_scores:
        avg = round(sum(numeric_scores) / len(numeric_scores))
        merged["code_overall_impression"] = {
            "value": str(max(1, min(10, avg))),
            "confidence": min(0.95, 0.55 + 0.08 * len(numeric_scores)),
            "evidence": shorten_cell("; ".join(numeric_evidence), 350),
        }
    return merged


def normalize_deep_agent_metrics(metrics: Any) -> dict[str, dict[str, Any]]:
    normalized: dict[str, dict[str, Any]] = {}
    if not isinstance(metrics, dict):
        return normalized
    for key in DEEP_AGENT_KEYS:
        item = metrics.get(key, {})
        if isinstance(item, str):
            item = {"value": item, "confidence": 0.5, "evidence": "Deep agent returned a scalar value."}
        if not isinstance(item, dict):
            continue
        confidence = safe_float(item.get("confidence"), 0.0)
        normalized[key] = {
            "value": normalize_ai_metric_value(key, item.get("value", "unclear"), confidence),
            "confidence": confidence,
            "evidence": normalize_cell(item.get("evidence", "No evidence provided.")),
        }
    return normalized


def summarize_deep_review_for_prompt(deep_review: dict[str, Any]) -> dict[str, Any]:
    if not deep_review:
        return {}
    return {
        "agent_used": deep_review.get("agent_used", False),
        "files_reviewed": deep_review.get("files_reviewed", [])[:50],
        "static_scan": deep_review.get("static_scan", {}),
        "metrics": deep_review.get("metrics", {}),
    }


def yes_unclear_from_samples(samples: list[Any], label: str) -> dict[str, Any]:
    if samples:
        return {
            "value": f"yes ({label})",
            "confidence": 0.60,
            "evidence": join_sample_lines(samples[:8]),
        }
    return {"value": "unclear", "confidence": 0.35, "evidence": f"No {label} found by static scan."}


def join_sample_lines(samples: list[Any]) -> str:
    parts = []
    for sample in samples:
        if isinstance(sample, dict):
            parts.append(f"{sample.get('path')}:{sample.get('line')} {sample.get('text')}")
        else:
            parts.append(str(sample))
    return shorten_cell("; ".join(parts), 350)


def append_limited(items: list[Any], value: Any, limit: int, key: Any | None = None) -> None:
    items.append(value)
    if key is not None:
        items.sort(key=key, reverse=True)
    if len(items) > limit:
        del items[limit:]


def sample_line(path: str, line_no: int, text: str) -> dict[str, Any]:
    return {"path": path, "line": line_no, "text": shorten_cell(text, 160)}


def looks_generated_or_vendor(rel: str) -> bool:
    lower = rel.lower()
    return any(
        part in lower
        for part in [
            "/third_party/",
            "/3rdparty/",
            "/external/",
            "/extern/",
            "/vendor/",
            "/generated/",
            "/build/",
            "/dist/",
            "/node_modules/",
            ".pb.cc",
            ".pb.h",
            "moc_",
            "qrc_",
        ]
    )


def numeric_literal_signal(line: str) -> bool:
    if line.lstrip().startswith(("#include", "import ", "from ")):
        return False
    if re.search(r"\b(v|version|copyright|license)\b", line, re.IGNORECASE):
        return False
    return bool(re.search(r"(?<![A-Za-z_])(?:[2-9]\d*|\d+\.\d+)(?![A-Za-z_])", line))


def file_has_mixed_indentation(lines: list[str]) -> bool:
    tab_indents = 0
    space_indents = 0
    for line in lines[:500]:
        if line.startswith("\t"):
            tab_indents += 1
        elif line.startswith("    "):
            space_indents += 1
    return tab_indents > 5 and space_indents > 5


def extract_function_signatures(lines: list[str], ext: str) -> list[tuple[str, str]]:
    signatures: list[tuple[str, str]] = []
    for line in lines:
        stripped = line.strip()
        if ext == ".py":
            match = re.match(r"def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)", stripped)
        else:
            match = re.match(r"(?:[\w:<>,~*&\s]+)\s+([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*(?:const)?\s*(?:\{|$)", stripped)
        if not match:
            continue
        name = match.group(1)
        params = normalize_params(match.group(2))
        if name not in {"if", "for", "while", "switch", "catch"}:
            signatures.append((name, params))
    return signatures[:500]


def normalize_params(params: str) -> str:
    names = []
    for raw in params.split(","):
        token = raw.strip()
        if not token:
            continue
        token = token.split("=")[0].strip()
        pieces = re.split(r"\s+", token.replace("&", " ").replace("*", " "))
        names.append(pieces[-1] if pieces else token)
    return ",".join(names[:12])


def build_code_excerpt(path: Path, max_chars: int) -> str:
    text = read_text_lossy(path)
    if len(text) <= max_chars:
        return text
    lines = text.splitlines()
    signal_indexes = [
        index
        for index, line in enumerate(lines)
        if re.search(r"\b(throw|raise|assert|invalid|error|algorithm|solver|performance|benchmark|getline|readline)\b", line, re.IGNORECASE)
    ]
    chunks_text = ["\n".join(lines[:80])]
    for index in signal_indexes[:8]:
        start = max(0, index - 5)
        end = min(len(lines), index + 6)
        chunks_text.append(f"\n// excerpt around line {index + 1}\n" + "\n".join(lines[start:end]))
    chunks_text.append("\n".join(lines[-50:]))
    excerpt = "\n...\n".join(chunks_text)
    return excerpt[:max_chars]


def chunks(items: list[Any], size: int) -> list[list[Any]]:
    return [items[index : index + size] for index in range(0, len(items), size)]


def yes_no_item(found: list[str], yes_value: str, no_value: str, label: str) -> dict[str, Any]:
    if found:
        return {
            "value": f"{yes_value} ({', '.join(found[:5])})",
            "evidence": f"Found {label}: {', '.join(found[:12])}",
            "confidence": 0.85,
            "needs_review": False,
        }
    return {
        "value": no_value,
        "evidence": f"No {label} found by path scan.",
        "confidence": 0.65,
        "needs_review": True,
    }


def collect_document_context(repo: Path | None) -> dict[str, Any]:
    if repo is None or not repo.exists():
        return {}
    candidates: list[Path] = []
    preferred_patterns = [
        "README*",
        "CONTRIBUTING*",
        "CHANGELOG*",
        "RELEASE*",
        "docs/index*",
        "docs/README*",
        "doc/index*",
        "doc/README*",
        "CMakeLists.txt",
    ]
    for pattern in preferred_patterns:
        candidates.extend(repo.glob(pattern))
    seen: set[Path] = set()
    docs = []
    for path in candidates:
        if path in seen or not path.is_file() or is_binary_file(path):
            continue
        seen.add(path)
        text = read_text_lossy(path)
        docs.append({"path": path.relative_to(repo).as_posix(), "excerpt": text[:3000]})
        if len(docs) >= 8:
            break
    path_samples = [path.relative_to(repo).as_posix() for path in tracked_files(repo)[:200]]
    return {"documents": docs, "path_samples": path_samples[:120]}


def fallback_ai_like_results(context: SoftwareContext, heuristics: dict[str, Any]) -> dict[str, dict[str, Any]]:
    ci = heuristics.get("ci", {}).get("value", "unclear")
    tests = heuristics.get("unit_tests", {}).get("value", "unclear")
    api_docs = heuristics.get("api_docs", {}).get("value", "unclear")
    dev_env = heuristics.get("dev_env_docs", {}).get("value", "unclear")
    return {
        "funding": {"value": "unclear", "confidence": 0.0, "evidence": "Funding requires web/document review."},
        "platforms": {"value": "unclear", "confidence": 0.0, "evidence": "Platform support requires documentation review."},
        "performance": {"value": "unclear", "confidence": 0.0, "evidence": "Performance evidence requires documentation/code review."},
        "requirements": {"value": api_docs if api_docs.startswith("yes") else "unclear", "confidence": 0.35, "evidence": "Fallback based on documentation path scan."},
        "correctness_tools": {
            "value": f"automated testing; CI evidence ({tests}; {ci})" if tests.startswith("yes") or ci.startswith("yes") else "unclear",
            "confidence": 0.45,
            "evidence": "Fallback based on tests and CI path scans.",
        },
        "unexpected_input": {"value": "unclear", "confidence": 0.0, "evidence": "Requires targeted code review."},
        "newline_handling": {"value": "unclear", "confidence": 0.0, "evidence": "Requires targeted input parsing review."},
        "coding_standard": {"value": "unclear", "confidence": 0.0, "evidence": "Requires repository documentation review."},
        "identifier_quality": {"value": "unclear", "confidence": 0.0, "evidence": "Requires code review."},
        "hard_coded_constants": {"value": "unclear", "confidence": 0.0, "evidence": "Requires static analysis/code review."},
        "comment_clarity": {"value": "unclear", "confidence": 0.0, "evidence": "Requires code review."},
        "parameter_order": {"value": "unclear", "confidence": 0.0, "evidence": "Requires API/code review."},
        "algorithm_mentions": {"value": "unclear", "confidence": 0.0, "evidence": "Requires documentation/code review."},
        "modularity": {"value": "unclear", "confidence": 0.0, "evidence": "Requires architecture review."},
        "code_overall_impression": {"value": "unclear", "confidence": 0.0, "evidence": "Requires human review."},
        "development_process": {"value": "unclear", "confidence": 0.0, "evidence": "Requires project documentation review."},
        "development_status_docs": {"value": "unclear", "confidence": 0.0, "evidence": "Requires project documentation review."},
        "development_environment": {"value": dev_env, "confidence": 0.45, "evidence": "Fallback based on development environment file scan."},
        "development_overall_impression": {"value": "unclear", "confidence": 0.0, "evidence": "Requires human review."},
    }


def normalize_ai_response(parsed: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if "metrics" in parsed and isinstance(parsed["metrics"], dict):
        parsed = parsed["metrics"]
    normalized: dict[str, dict[str, Any]] = {}
    for key in AI_METRIC_KEYS:
        item = parsed.get(key, {})
        if isinstance(item, str):
            item = {"value": item, "confidence": 0.5, "evidence": "AI returned a scalar value."}
        if not isinstance(item, dict):
            item = {"value": "unclear", "confidence": 0.0, "evidence": "AI returned an invalid item."}
        normalized[key] = {
            "value": item.get("value", "unclear"),
            "confidence": safe_float(item.get("confidence"), 0.0),
            "evidence": item.get("evidence", "No evidence provided."),
        }
    return normalized


def normalize_ai_metric_value(key: str, value: Any, confidence: float) -> str:
    text = normalize_cell(value)
    lower = text.lower()
    if lower in {"", "unknown", "not enough information", "not specified", "none", "null"}:
        return "unclear"

    if key == "funding":
        if lower.startswith(("funded", "unfunded", "unclear")):
            return text
        if "funded" in lower or "sponsor" in lower or "grant" in lower:
            return f"funded ({shorten_cell(text)})"
        return "unclear"

    if key == "platforms":
        if lower.startswith("unclear"):
            return "unclear"
        platforms: list[str] = []
        if "windows" in lower or "win32" in lower:
            platforms.append("Windows")
        if "linux" in lower or "ubuntu" in lower or "unix" in lower:
            platforms.append("Linux")
        if "macos" in lower or "mac os" in lower or "os x" in lower or "darwin" in lower:
            platforms.append("OS X")
        if "android" in lower:
            platforms.append("Android")
        if not platforms and text:
            platforms.append(f"other ({shorten_cell(text)})")
        return ", ".join(dict.fromkeys(platforms)) if platforms else "unclear"

    if key in {"code_overall_impression", "development_overall_impression"}:
        match = re.search(r"\b(10|[1-9])\b", text)
        return match.group(1) if match else "unclear"

    if key == "correctness_tools":
        if lower.startswith("unclear"):
            return "unclear"
        if any(word in lower for word in ["test", "ci", "assert", "doxygen", "sphinx", "javadoc", "model checking", "symbolic"]):
            return text
        return "unclear"

    if key in {"newline_handling", "coding_standard", "identifier_quality", "comment_clarity", "parameter_order", "algorithm_mentions", "modularity"}:
        return normalize_yes_no_like(text, confidence, allow_na=True)

    if key in {"performance", "requirements", "unexpected_input", "hard_coded_constants", "development_process", "development_status_docs", "development_environment"}:
        return normalize_yes_no_like(text, confidence, allow_na=False)

    return text or "unclear"


def normalize_yes_no_like(text: str, confidence: float, *, allow_na: bool) -> str:
    lower = text.lower()
    if lower.startswith(("yes", "no", "unclear")):
        return text
    if allow_na and lower.startswith(("n/a", "na", "not applicable")):
        return "n/a"
    if lower in {"unknown", "moderate", "medium", "high", "low"}:
        return "unclear"
    positive_words = ["available", "documented", "present", "found", "uses", "well-structured", "modular", "clear"]
    negative_words = ["not found", "not documented", "absent", "poor", "inconsistent"]
    if any(word in lower for word in negative_words):
        return f"no ({shorten_cell(text)})"
    if confidence >= 0.75 and any(word in lower for word in positive_words):
        return f"yes ({shorten_cell(text)})"
    return "unclear"


def shorten_cell(text: str, limit: int = 120) -> str:
    text = normalize_cell(text)
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def extract_json_object(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?", "", text).strip()
        text = re.sub(r"```$", "", text).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("No JSON object found in AI response.")
    return text[start : end + 1]


def redact_repo_meta(meta: dict[str, Any] | None) -> dict[str, Any]:
    if not meta:
        return {}
    keys = ["full_name", "description", "homepage", "license", "topics", "default_branch", "stargazers_count", "forks_count", "open_issues_count"]
    return {key: meta.get(key) for key in keys}


def map_license(license_info: dict[str, Any]) -> str:
    spdx = str(license_info.get("spdx_id") or "").strip()
    name = str(license_info.get("name") or "").strip()
    label = spdx if spdx and spdx != "NOASSERTION" else name
    lower = label.lower()
    if not label or lower in {"other", "noassertion"}:
        return "unclear"
    if "mit" in lower:
        return "mit"
    if "bsd" in lower:
        return "bsd"
    if "gpl" in lower:
        return f"GNU GPL ({label})"
    return f"other ({label})"


def map_languages(languages: dict[str, int]) -> str:
    if not languages:
        return "unclear"
    allowed = {
        "fortran": "FORTRAN",
        "matlab": "Matlab",
        "c": "C",
        "c++": "C++",
        "java": "Java",
        "r": "R",
        "ruby": "Ruby",
        "python": "Python",
        "cython": "Cython",
        "basic": "BASIC",
        "pascal": "Pascal",
        "idl": "IDL",
    }
    names: list[str] = []
    others: list[str] = []
    for language, _bytes in sorted(languages.items(), key=lambda item: item[1], reverse=True):
        key = language.lower()
        if key in allowed:
            names.append(allowed[key])
        else:
            others.append(language)
    if others:
        names.append(f"other ({', '.join(others[:8])})")
    return ", ".join(dict.fromkeys(names)) if names else "unclear"


def current_version(context: SoftwareContext) -> str:
    if context.latest_release and context.latest_release.get("tag_name"):
        return str(context.latest_release["tag_name"])
    if context.latest_tag and context.latest_tag.get("name"):
        return str(context.latest_tag["name"])
    return "unclear"


def fallback_pushed_date(context: SoftwareContext) -> str:
    if context.repo_meta and context.repo_meta.get("pushed_at"):
        return iso_date(str(context.repo_meta["pushed_at"]))
    return "unclear"


def iso_date(value: str) -> str:
    match = re.match(r"(\d{4}-\d{2}-\d{2})", value)
    return match.group(1) if match else value[:10]


def str_or_unclear(value: Any) -> str:
    if value is None:
        return "unclear"
    return str(value)


def normalize_cell(value: Any) -> str:
    if value is None:
        return "unclear"
    text = str(value).replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def safe_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def summarize_error(stderr: str) -> str:
    text = normalize_cell(stderr)
    return text[:500] if text else "unknown error"


def hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def cache_path(cache_dir: Path, key: str) -> Path:
    digest = hash_text(key)
    return cache_dir / f"{digest}.json"


def read_cache(cache_dir: Path, key: str) -> Any:
    path = cache_path(cache_dir, key)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def write_cache(cache_dir: Path, key: str, data: Any) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_path(cache_dir, key)
    tmp = path.with_suffix(f".{os.getpid()}.{threading.get_ident()}.{time.time_ns()}.tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def select_software(all_software: list[str], selectors: list[str], limit: int | None) -> list[str]:
    selected = all_software
    if selectors:
        wanted = {item.strip().lower() for selector in selectors for item in selector.split(",") if item.strip()}
        selected = [software for software in all_software if software.strip().lower() in wanted]
        missing = sorted(wanted - {software.strip().lower() for software in selected})
        if missing:
            print(f"[warn] Unknown software selector(s): {', '.join(missing)}", file=sys.stderr)
    if limit is not None:
        selected = selected[:limit]
    return selected


def clone_metric_table(table: MetricTable) -> MetricTable:
    return MetricTable(
        fieldnames=list(table.fieldnames),
        rows=[dict(row) for row in table.rows],
        software_columns=list(table.software_columns),
    )


def collect_single_software(
    software: str,
    base_table: MetricTable,
    original_rows: list[dict[str, str]],
    env: dict[str, str],
    output_dir: Path,
    repos_dir: Path,
    cache_dir: Path,
    args: argparse.Namespace,
) -> tuple[str, list[dict[str, str]], list[Evidence], str | None]:
    table = clone_metric_table(base_table)
    blank_selected_cells(table, [software])
    collector = Collector(
        table,
        original_rows,
        env,
        output_dir,
        repos_dir,
        cache_dir,
        skip_ai=args.skip_ai,
        skip_clone=args.skip_clone,
        force_refresh=args.force_refresh,
        ai_min_confidence=args.ai_min_confidence,
        git_timeout=args.git_timeout,
        clone_timeout=args.clone_timeout,
        deep_agent_review=args.deep_agent_review,
        deep_max_files=args.deep_max_files,
        deep_batch_files=args.deep_batch_files,
        deep_file_chars=args.deep_file_chars,
        deep_timeout=args.deep_timeout,
    )
    try:
        collector.collect([software])
        return software, table.rows, collector.evidence, None
    except Exception as exc:  # noqa: BLE001 - keep parallel batch runs alive.
        message = f"{type(exc).__name__}: {exc}"
        evidence: list[Evidence] = []
        for row in table.rows:
            metric = (row.get("Metric") or "").strip()
            if not metric:
                row[software] = ""
                continue
            row[software] = "unclear"
            evidence.append(
                Evidence(
                    software=software,
                    metric=metric,
                    value="unclear",
                    source_type=SOURCE_TYPES["fallback"],
                    source="parallel worker error",
                    evidence=message,
                    confidence=0.0,
                    needs_review=True,
                    repo_url="",
                )
            )
        return software, table.rows, evidence, message


def collect_parallel(
    table: MetricTable,
    original_rows: list[dict[str, str]],
    env: dict[str, str],
    output_dir: Path,
    repos_dir: Path,
    cache_dir: Path,
    selected: list[str],
    args: argparse.Namespace,
) -> tuple[list[Evidence], list[tuple[str, str]]]:
    worker_count = max(1, min(args.workers, len(selected)))
    print(f"[parallel] collecting {len(selected)} software columns with {worker_count} workers", flush=True)
    evidence: list[Evidence] = []
    errors: list[tuple[str, str]] = []
    results: dict[str, tuple[list[dict[str, str]], list[Evidence], str | None]] = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_to_software = {
            executor.submit(
                collect_single_software,
                software,
                table,
                original_rows,
                env,
                output_dir,
                repos_dir,
                cache_dir,
                args,
            ): software
            for software in selected
        }
        for future in concurrent.futures.as_completed(future_to_software):
            software = future_to_software[future]
            try:
                returned_software, rows, worker_evidence, error = future.result()
            except Exception as exc:  # noqa: BLE001 - defensive; collect_single_software should catch.
                returned_software = software
                rows = []
                worker_evidence = []
                error = f"{type(exc).__name__}: {exc}"
            results[returned_software] = (rows, worker_evidence, error)
            if error:
                errors.append((returned_software, error))
                print(f"[parallel] {returned_software} failed: {error}", flush=True)
            else:
                print(f"[parallel] {returned_software} done", flush=True)

    for software in selected:
        rows, worker_evidence, error = results.get(software, ([], [], "missing worker result"))
        if not rows:
            errors.append((software, error or "missing worker result"))
            continue
        for index, row in enumerate(rows):
            table.rows[index][software] = row.get(software, "")
        evidence.extend(worker_evidence)
    return evidence, errors


def blank_selected_cells(table: MetricTable, software_columns: list[str]) -> None:
    for row in table.rows:
        if not (row.get("Metric") or "").strip():
            for software in software_columns:
                row[software] = ""
            continue
        for software in software_columns:
            row[software] = ""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect software metrics into the need_automic_metic CSV layout.")
    parser.add_argument("--input", default=DEFAULT_INPUT, help="Input CSV path.")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, help="Output directory.")
    parser.add_argument("--repos-dir", default=DEFAULT_REPOS_DIR, help="Directory for cloned repositories.")
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR, help="Directory for cached API/AI responses.")
    parser.add_argument("--software", action="append", default=[], help="Software column to process; can be repeated or comma-separated.")
    parser.add_argument("--limit", type=int, default=None, help="Process only the first N selected software columns.")
    parser.add_argument("--workers", type=int, default=1, help="Number of software columns to collect in parallel.")
    parser.add_argument("--skip-ai", action="store_true", help="Skip DeepSeek calls and use heuristic fallback for AI-assisted metrics.")
    parser.add_argument("--skip-clone", action="store_true", help="Skip clone/pull and mark local-repository metrics as unclear.")
    parser.add_argument("--force-refresh", action="store_true", help="Ignore API/AI cache entries and fetch again.")
    parser.add_argument("--ai-min-confidence", type=float, default=0.75, help="Below this AI confidence, evidence rows are marked needs_review.")
    parser.add_argument("--deep-agent-review", action="store_true", help="Run a deeper repository code review for subjective code-quality metrics.")
    parser.add_argument("--deep-max-files", type=int, default=30, help="Maximum representative code files to send to the deep AI reviewer per repository.")
    parser.add_argument("--deep-batch-files", type=int, default=6, help="Number of code files per deep-review AI batch.")
    parser.add_argument("--deep-file-chars", type=int, default=5000, help="Maximum excerpt characters per file for deep AI review.")
    parser.add_argument("--deep-timeout", type=int, default=180, help="Timeout for each deep-review AI request in seconds.")
    parser.add_argument("--git-timeout", type=int, default=180, help="Timeout for ordinary git commands in seconds.")
    parser.add_argument("--clone-timeout", type=int, default=1800, help="Timeout for clone/fetch/numstat commands in seconds.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path.cwd()
    input_path = root / args.input
    output_dir = root / args.output_dir
    repos_dir = root / args.repos_dir
    cache_dir = root / args.cache_dir

    table = load_table(input_path)
    selected = select_software(table.software_columns, args.software, args.limit)
    if not selected:
        print("No software columns selected.", file=sys.stderr)
        return 2
    if args.workers < 1:
        print("--workers must be at least 1.", file=sys.stderr)
        return 2

    original_rows = [dict(row) for row in table.rows]
    blank_selected_cells(table, selected)
    env = load_env(root / ".env")
    errors: list[tuple[str, str]] = []
    if args.workers > 1 and len(selected) > 1:
        evidence, errors = collect_parallel(table, original_rows, env, output_dir, repos_dir, cache_dir, selected, args)
    else:
        collector = Collector(
            table,
            original_rows,
            env,
            output_dir,
            repos_dir,
            cache_dir,
            skip_ai=args.skip_ai,
            skip_clone=args.skip_clone,
            force_refresh=args.force_refresh,
            ai_min_confidence=args.ai_min_confidence,
            git_timeout=args.git_timeout,
            clone_timeout=args.clone_timeout,
            deep_agent_review=args.deep_agent_review,
            deep_max_files=args.deep_max_files,
            deep_batch_files=args.deep_batch_files,
            deep_file_chars=args.deep_file_chars,
            deep_timeout=args.deep_timeout,
        )
        collector.collect(selected)
        evidence = collector.evidence

    csv_path = output_dir / "need_automic_metic_filled.csv"
    xlsx_path = output_dir / "need_automic_metic_filled.xlsx"
    evidence_path = output_dir / "evidence.csv"
    save_csv(csv_path, table)
    save_xlsx(xlsx_path, table)
    save_evidence(evidence_path, evidence)

    print(f"[done] wrote {csv_path}")
    print(f"[done] wrote {xlsx_path}")
    print(f"[done] wrote {evidence_path}")
    if errors:
        print("[done] completed with worker errors:", file=sys.stderr)
        for software, error in errors:
            print(f"  - {software}: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
