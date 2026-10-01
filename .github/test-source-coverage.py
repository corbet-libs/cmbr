"""Exercise the actual source gate against LLVM-format acceptance/refusal cases."""
import copy
import hashlib
import json
import tempfile
import contextlib
import io
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('gate', Path(__file__).parent / 'check-source-coverage.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
ROOT = Path('/tmp/policy-coverage-fixture')
RAW = {'type': 'llvm.coverage.json.export', 'data': [{'files': [{'filename': str(ROOT / 'src/lib.rs'), 'branches': [[1, 1, 1, 2, 2, 1, 0, 0, 4]], 'summary': {'lines': {'count': 2, 'covered': 2}, 'branches': {'count': 2, 'covered': 2}}}]}]}
TEXT = f'{ROOT}/src/lib.rs:\n 1| 3|source\n 2| 1|source\n'
LCOV = f'SF:{ROOT}/src/lib.rs\nDA:1,3\nDA:2,1\nLF:2\nLH:2\nBRDA:1,0,0,2\nBRDA:1,0,1,1\nBRF:2\nBRH:2\nend_of_record\n'


class GateTests(unittest.TestCase):
    def test_complete_source_coverage(self):
        gate.check(LCOV, RAW, ROOT, TEXT)

    def test_merged_generic_source_is_not_instantiation_coverage(self):
        raw = copy.deepcopy(RAW)
        file = raw['data'][0]['files'][0]
        file['branches'].append(file['branches'][0][:])
        file['summary']['lines'] = {'count': 3, 'covered': 2}
        file['summary']['branches'] = {'count': 4, 'covered': 3}
        report = LCOV.replace('LF:2', 'LF:3').replace('BRF:2', 'BRF:4').replace('BRH:2', 'BRH:3')
        gate.check(report, raw, ROOT, TEXT)

    def test_no_instrumentable_branches(self):
        value = '\n'.join(row for row in LCOV.splitlines() if not row.startswith('BR'))
        raw = copy.deepcopy(RAW)
        raw['data'][0]['files'][0]['summary']['branches'] = {'count': 0, 'covered': 0}
        raw['data'][0]['files'][0]['branches'] = []
        gate.check(value, raw, ROOT, TEXT)

    def test_refuses_missing_malformed_or_uncovered_records(self):
        bad = [
            '', LCOV.replace('DA:2,1\n', ''), LCOV.replace('DA:2,1', 'DA:2,0'),
            LCOV.replace('BRDA:1,0,1,1', 'BRDA:1,0,1,0'),
            LCOV.replace('BRDA:1,0,1,1\n', ''), LCOV.replace('DA:2,1', 'DA:2,0').replace('LH:2', 'LH:1'),
            LCOV.replace('BRDA:1,0,1,1', 'BRDA:1,0,1,0').replace('BRH:2', 'BRH:1'),
            LCOV.replace('BRDA:1,0,1,1', 'BRDA:1,0,1,-').replace('BRH:2', 'BRH:1'),
            LCOV.replace('DA:1,3', 'DA:1,-1'),
            LCOV.replace('BRDA:1,0,0,2', 'BRDA:1,0,0,-2'),
            LCOV.replace('DA:1,3', 'DA:1,3\nDA:1,3'),
            LCOV.replace('BRDA:1,0,0,2', 'BRDA:1,0,0,2\nBRDA:1,0,0,2'),
            LCOV.replace('LF:2', 'LF:3'), LCOV.replace('BRH:2', 'BRH:1'),
            LCOV.replace('LF:2', 'LF:2\nLF:2'),
            LCOV.replace('end_of_record\n', ''), LCOV + LCOV,
            LCOV.replace('/src/lib.rs', '/tests/lib.rs'),
            LCOV.replace('/src/lib.rs', '/../outside.rs'),
            LCOV.replace('DA:1,3', 'DA:0,3'), LCOV + 'DA:4,1\n',
            LCOV.replace('LF:2\n', ''), LCOV.replace('BRF:2\n', ''),
        ]
        for index, report in enumerate(bad):
            with self.subTest(index=index), self.assertRaises(ValueError):
                gate.check(report, RAW, ROOT, TEXT)

    def test_companion_inventory_cannot_be_missing_or_truncated(self):
        raw = copy.deepcopy(RAW)
        raw['data'][0]['files'].append({'filename': str(ROOT / 'src/missing.rs'), 'branches': [], 'summary': copy.deepcopy(RAW['data'][0]['files'][0]['summary'])})
        for report in ({}, {'type': 'other', 'data': []}, raw):
            with self.subTest(report=report), self.assertRaises(ValueError):
                gate.check(LCOV, report, ROOT, TEXT)


    def test_upstream_single_file_report_omits_heading(self):
        gate.check(LCOV, RAW, ROOT, TEXT.split('\n', 1)[1])

    def test_duplicate_raw_source_refused(self):
        raw = copy.deepcopy(RAW)
        raw['data'][0]['files'].append(copy.deepcopy(raw['data'][0]['files'][0]))
        with self.assertRaises(ValueError):
            gate.check(LCOV, raw, ROOT, TEXT)

    def test_annotated_inventory_and_hit_consistency(self):
        for text in ['', TEXT + TEXT, TEXT.replace(' 2| 1|source\n', ''), TEXT.replace('2| 1|', '2| 0|')]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                gate.check(LCOV, RAW, ROOT, text)


class ExceptionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / 'src').mkdir()
        (self.root / '.github').mkdir()
        self.source = self.root / 'src/lib.rs'
        self.source.write_text('predicate\nmapper\n')
        self.manifest = self.root / '.github/coverage-exclusions.json'
        self.lcov = LCOV.replace(str(ROOT), str(self.root)).replace('BRDA:1,0,1,1', 'BRDA:1,0,1,0').replace('BRH:2', 'BRH:1')
        self.raw = json.loads(json.dumps(RAW).replace(str(ROOT), str(self.root)))
        self.raw['data'][0]['files'][0]['branches'][0][5] = 0
        self.raw['data'][0]['files'][0]['summary']['branches']['covered'] = 1
        self.text = TEXT.replace(str(ROOT), str(self.root))
        self.branch = {'file': 'src/lib.rs', 'line': 1, 'source': 'predicate',
                       'branch': {'block': 0, 'id': 1}, 'reason': 'Fixture invariant',
                       'evidence': 'Fixture evidence only',
                       'evidence_sources': {'src/lib.rs': hashlib.sha256(self.source.read_bytes()).hexdigest()}}

    def check(self, entries):
        self.manifest.write_text(json.dumps(entries))
        gate.check(self.lcov, self.raw, self.root, self.text)

    def test_exact_unreachable_branch_keeps_the_other_arm_and_all_inventories(self):
        self.check([self.branch])
        self.lcov = self.lcov.replace('BRDA:1,0,0,2\n', '')
        with self.assertRaises(ValueError):
            self.check([self.branch])

    def test_refuses_executed_missing_duplicate_or_unpinned_branch(self):
        for change in [
            {'branch': {'block': 0, 'id': 0}},
            {'branch': {'block': 1, 'id': 1}},
            {'branch': {'block': 0, 'id': -1}},
            {'branch': {'block': 0, 'id': True}},
            {'branch': {'block': 0}},
            {'evidence_sources': {}}, {'reason': ''}, {'evidence': ''},
            {'source': 'changed'}, {'line': 0}, {'line': True},
        ]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.check([self.branch | change])
        with self.assertRaises(ValueError):
            self.check([self.branch, self.branch])

    def test_invariant_source_change_elsewhere_invalidates_exception(self):
        self.source.write_text('predicate\nchanged earlier validation\n')
        with self.assertRaises(ValueError):
            self.check([self.branch])

    def test_wrong_target_cannot_hide_a_missing_arm(self):
        with self.assertRaises(ValueError):
            self.check([self.branch | {'target': 'wasm'}])

    def test_line_exception_cannot_hide_a_branch_or_executed_line(self):
        line = {key: value for key, value in self.branch.items() if key != 'branch'}
        with self.assertRaises(ValueError):
            self.check([line])
        self.lcov = self.lcov.replace('DA:2,1', 'DA:2,0').replace('LH:2', 'LH:1')
        self.raw['data'][0]['files'][0]['summary']['lines']['covered'] = 1
        self.text = self.text.replace('2| 1|', '2| 0|')
        self.check([self.branch, line | {'line': 2, 'source': 'mapper'}])
        self.text = self.text.replace(' 2| 0|source\n', '')
        with self.assertRaises(ValueError):
            self.check([self.branch, line | {'line': 2, 'source': 'mapper'}])

    def test_unreachable_condition_requires_all_source_bound_arms(self):
        line = {key: value for key, value in self.branch.items() if key != 'branch'}
        self.lcov = self.lcov.replace('DA:1,3', 'DA:1,0').replace('LH:2', 'LH:1')
        self.lcov = self.lcov.replace('BRDA:1,0,0,2', 'BRDA:1,0,0,0').replace('BRH:1', 'BRH:0')
        source = self.raw['data'][0]['files'][0]
        source['summary']['lines']['covered'] = 1
        source['summary']['branches']['covered'] = 0
        source['branches'][0][4] = 0
        self.text = self.text.replace('1| 3|', '1| 0|')
        first = self.branch | {'branch': {'block': 0, 'id': 0}}
        for entries in ([line], [line, first], [line, self.branch]):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                self.check(entries)
        self.check([line, first, self.branch])
        self.lcov = self.lcov.replace('BRDA:1,0,0,0\n', '')
        with self.assertRaises(ValueError):
            self.check([line, first, self.branch])

    def proof_dependency(self):
        identity = {'version': '0.0.0', 'source': 'git+https://github.com/corbet-foss/proof?branch=main#' + 'a' * 40}
        text = '[[package]]\nname = "proof"\nversion = "0.0.0"\nsource = "' + identity['source'] + '"\n'
        (self.root / 'Cargo.lock').write_text(text)
        return self.branch | {'evidence_packages': {'proof': identity}}, text

    def test_exact_proof_dependency_ignores_unrelated_packages(self):
        entry, text = self.proof_dependency()
        self.check([entry])
        (self.root / 'Cargo.lock').write_text(text + '\n[[package]]\nname = "other"\nversion = "2"\n')
        self.check([entry])
        (self.root / 'Cargo.lock').write_text(text.replace('a' * 40, 'b' * 40))
        with self.assertRaises(ValueError):
            self.check([entry])

    def test_proof_dependency_refuses_missing_duplicate_or_wrong_version(self):
        entry, text = self.proof_dependency()
        for changed in ('[[package]]\nname="other"\n', text + text, text.replace('0.0.0', '1.0.0')):
            (self.root / 'Cargo.lock').write_text(changed)
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.check([entry])

    def test_proof_dependency_refuses_weak_or_malformed_identity(self):
        entry, _ = self.proof_dependency()
        for value in ([], {'proof': {}}, {'proof': {'version': '0.0.0', 'source': 'branch=main'}}, {'proof': {'version': True, 'source': 'a' * 40}}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.check([entry | {'evidence_packages': value}])


if __name__ == '__main__':
    with contextlib.redirect_stdout(io.StringIO()):
        unittest.main()
