"""Closed signing workflow context/export controls; not a general YAML validator."""
import resource

for limit, value in ((resource.RLIMIT_AS, 268435456), (resource.RLIMIT_CPU, 30),
                     (resource.RLIMIT_FSIZE, 2097152), (resource.RLIMIT_NOFILE, 64),
                     (resource.RLIMIT_CORE, 0)):
    inherited_soft, inherited_hard = resource.getrlimit(limit)
    finite = [bound for bound in (inherited_soft, inherited_hard)
              if bound != resource.RLIM_INFINITY]
    admitted = min([value] + finite)
    resource.setrlimit(limit, (admitted, admitted))

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CAP = 16384
HEADER = """name: Mandatory ML-DSA-87 manifest signing controls
on: [push, pull_request]
permissions:
  contents: read
jobs:
  actual-provider-and-signed-controls:
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    steps:
"""
EXPORT = r"""      - name: Declare runner-local signing directories
        run: |
          printf '%s\n' \
            "SAST_MLDSA87_SOURCE=$RUNNER_TEMP/manifest-signing/source" \
            "SAST_MLDSA87_BUILD=$RUNNER_TEMP/manifest-signing/normal" \
            "SAST_MLDSA87_RNG_FAULT_ROOT=$RUNNER_TEMP/manifest-signing" >> "$GITHUB_ENV"
"""


def workflow_text():
    path = ROOT / '.github/workflows/manifest-signing.yml'
    if path.is_symlink() or not path.is_file():
        raise ValueError('regular workflow source required')
    with path.open('rb') as stream:
        raw = stream.read(CAP + 1)
    if len(raw) > CAP:
        raise ValueError('workflow byte cap')
    return raw.decode('ascii')


def validate_workflow(text):
    if type(text) is not str or len(text) > CAP or not text.startswith(HEADER):
        raise ValueError('closed signing job header changed or job env inserted')
    if '${{' in text or '\t' in text:
        raise ValueError('expression/tab outside closed runtime-export profile')
    if text.count(EXPORT) != 1:
        raise ValueError('exact quoted three-path export required once')
    export_run = text.index(EXPORT) + EXPORT.index('        run:')
    if text.index('        run:') != export_run:
        raise ValueError('directory export must be first runner command')
    if text.count('$GITHUB_ENV') != 1 or text.count('$RUNNER_TEMP') != 3:
        raise ValueError('unexpected environment export count')


class WorkflowContextControls(unittest.TestCase):
    def test_current_closed_profile(self):
        validate_workflow(workflow_text())

    def test_previous_invalid_runner_job_context_refused(self):
        text = workflow_text()
        invalid = text.replace('    steps:\n', '    env:\n'
            '      SAST_MLDSA87_SOURCE: ${{ runner.temp }}/manifest-signing/source\n'
            '    steps:\n', 1)
        with self.assertRaisesRegex(ValueError, 'job env inserted'):
            validate_workflow(invalid)

    def test_inline_or_other_job_environment_refused(self):
        for declaration in ('    env: {SAST_MLDSA87_BUILD: value}\n',
                            '    environment: production\n'):
            with self.subTest(declaration=declaration):
                invalid = workflow_text().replace('    steps:\n', declaration + '    steps:\n', 1)
                with self.assertRaises(ValueError):
                    validate_workflow(invalid)

    def test_missing_changed_and_unquoted_exports_refused(self):
        text = workflow_text()
        mutations = (text.replace(EXPORT, ''),
                     text.replace('manifest-signing/normal', 'manifest-signing/source'),
                     text.replace('" >> "$GITHUB_ENV"', '" >> $GITHUB_ENV'),
                     text.replace('"SAST_MLDSA87_SOURCE=$RUNNER_TEMP/manifest-signing/source"',
                                  'SAST_MLDSA87_SOURCE=$RUNNER_TEMP/manifest-signing/source'))
        for invalid in mutations:
            with self.subTest(changed=invalid != text):
                with self.assertRaises(ValueError):
                    validate_workflow(invalid)

    def test_export_after_another_runner_command_refused(self):
        text = workflow_text().replace(EXPORT, '      - name: Too early\n'
            '        run: echo premature\n' + EXPORT)
        with self.assertRaisesRegex(ValueError, 'first runner command'):
            validate_workflow(text)

    def test_added_expression_and_extra_export_refused(self):
        for suffix in ('# ${{ runner.temp }}\n', '# $RUNNER_TEMP\n', '# $GITHUB_ENV\n'):
            with self.subTest(suffix=suffix):
                with self.assertRaises(ValueError):
                    validate_workflow(workflow_text() + suffix)


if __name__ == '__main__':
    unittest.main()
