#!/usr/bin/env python3
"""
Use OctoDoctor to analyze Argo CD manifests
"""

import json
import logging
import os
import shutil
import tempfile

import git

from megalinter import Linter, config, utils

OCTODOCTOR_OUTPUT_FOLDER = "octodoctor-output"
OCTODOCTOR_REPORT_SUB_FOLDER = "octodoctor"
OCTODOCTOR_TARGET_ARGS = ["-d", "--directory", "-e", "--export"]

logger = logging.getLogger(__name__)


class OctodoctorLinter(Linter):
    staging_directory = None

    # OctoDoctor always writes its reports in an octodoctor-output folder inside
    # the analyzed directory: the Argo CD files are copied in a temporary
    # directory outside of the workspace, so the analyzed sources are never
    # written while other linters walk them
    def build_lint_command(self, file=None) -> list:
        cmd = super().build_lint_command(file)
        if self.has_target_argument(cmd):
            return cmd
        self.staging_directory = self.stage_argocd_files()
        return cmd + ["--directory", self.staging_directory]

    def execute_lint_command(self, command):
        staging_directory = self.staging_directory
        try:
            return_code, return_stdout = super().execute_lint_command(command)
            if staging_directory is not None:
                return_stdout = return_stdout.replace(
                    staging_directory + os.path.sep, ""
                ).replace(staging_directory, ".")
                output_folder = os.path.join(
                    staging_directory, OCTODOCTOR_OUTPUT_FOLDER
                )
                return_stdout += self.build_failed_rules_summary(output_folder)
                self.save_octodoctor_reports(output_folder)
        finally:
            if staging_directory is not None:
                shutil.rmtree(staging_directory, ignore_errors=True)
                self.staging_directory = None
        return return_code, return_stdout

    def has_target_argument(self, cmd):
        for arg in cmd[len(self.cli_executable) :]:
            if arg in OCTODOCTOR_TARGET_ARGS or arg.startswith(
                ("--directory=", "--export=")
            ):
                return True
        return False

    def stage_argocd_files(self):
        staging_directory = tempfile.mkdtemp(prefix="megalinter-octodoctor-")
        workspace = os.path.abspath(self.workspace)
        argocd_files = self.list_argocd_files()
        for file in argocd_files:
            source_file = os.path.join(workspace, file)
            relative_file = os.path.relpath(source_file, workspace)
            if relative_file.startswith(".."):
                relative_file = os.path.basename(source_file)
            target_file = os.path.join(staging_directory, relative_file)
            os.makedirs(os.path.dirname(target_file), exist_ok=True)
            shutil.copyfile(source_file, target_file)
        self.log_lines_pre += [
            (
                f"[OctoDoctor] Analyzing {len(argocd_files)} Argo CD file(s) copied "
                "to a temporary directory, so that OctoDoctor reports are not "
                "written in the analyzed sources"
            )
        ]
        return staging_directory

    # Repository-wide rules (number of ApplicationSets, cluster generators...)
    # need every Argo CD file: when only updated files are listed, the whole
    # workspace is listed again with the same filters
    def list_argocd_files(self):
        if (
            self.master is None
            or self.master.validate_all_code_base is True
            or len(config.get_list(self.request_id, "MEGALINTER_FILES_TO_LINT", [])) > 0
        ):
            return list(self.files)
        all_files = self.master.list_files_all()
        ignored_files = []
        if self.master.ignore_gitignore_files is True:
            try:
                ignored_files = self.master.list_git_ignored_files()
            except git.InvalidGitRepositoryError as git_err:
                logger.warning(
                    f"[OctoDoctor] Unable to list git ignored files ({git_err!s})"
                )
        workspace_files = utils.filter_files(
            all_files=all_files,
            filter_regex_include=self.master.filter_regex_include,
            filter_regex_exclude=[self.master.filter_regex_exclude],
            file_names_regex=self.master.file_names_regex,
            file_extensions=self.master.file_extensions,
            ignored_files=ignored_files,
            ignore_generated_files=self.master.ignore_generated_files,
            workspace=self.workspace,
        )
        return utils.filter_files(
            all_files=workspace_files,
            filter_regex_include=self.filter_regex_include,
            filter_regex_exclude=[
                self.filter_regex_exclude_descriptor,
                self.filter_regex_exclude_linter,
            ],
            file_names_regex=self.file_names_regex,
            file_extensions=self.file_extensions,
            ignored_files=[],
            ignore_generated_files=False,
            file_names_not_ends_with=self.file_names_not_ends_with,
            file_contains_regex=self.file_contains_regex,
            file_contains_regex_extensions=self.file_contains_regex_extensions,
            files_sub_directory=self.files_sub_directory,
            lint_all_other_linters_files=self.lint_all_other_linters_files,
            workspace=self.workspace,
        )

    # OctoDoctor only logs counters on the console: list the failed rules and
    # their affected files from its JSON report
    def build_failed_rules_summary(self, output_folder):
        report_file = os.path.join(output_folder, "report.json")
        if not os.path.isfile(report_file):
            return ""
        with open(report_file, "r", encoding="utf-8") as report_handler:
            report = json.load(report_handler)
        failed_rules = (report.get("results") or {}).get("failed") or []
        if len(failed_rules) == 0:
            return ""
        lines = ["", f"OctoDoctor failed rules ({len(failed_rules)}):"]
        for rule in failed_rules:
            severity = str(rule.get("severity", "")).upper()
            lines += [
                f"[{rule.get('id', '')}] {severity}: {rule.get('description', '')}",
                f"  Documentation: {rule.get('documentationUrl', '')}",
            ]
            for affected_file in rule.get("affectedFiles") or []:
                lines += [f"  - {affected_file}"]
        return "\n".join(lines) + "\n"

    def save_octodoctor_reports(self, output_folder):
        if not os.path.isdir(output_folder) or not utils.can_write_report_files(self):
            return
        report_folder = os.path.join(self.report_folder, OCTODOCTOR_REPORT_SUB_FOLDER)
        shutil.copytree(output_folder, report_folder, dirs_exist_ok=True)
        self.log_lines_post += [
            f"[OctoDoctor] HTML, JSON and YAML reports saved in {report_folder}"
        ]
