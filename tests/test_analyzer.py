import unittest

from static_analyzer import analyze_source


class AnalyzerTests(unittest.TestCase):
    def test_selected_security_and_correctness_rules(self):
        source = """\
def collect(items=[]):
    assert items is not None
    if items == None:
        eval("1 + 2")
    try:
        pass
    except:
        pass
    return items
    print("unreachable")
"""
        findings = analyze_source(source, "sample.py")
        rules = {finding.rule for finding in findings}
        self.assertTrue(
            {"COR001", "COR002", "COR003", "COR004", "SEC001", "STY001"} <= rules
        )
        self.assertTrue(all(finding.path == "sample.py" for finding in findings))
        self.assertTrue(all(finding.line > 0 and finding.column > 0 for finding in findings))

    def test_subprocess_and_pickle_red_flags(self):
        findings = analyze_source(
            "import subprocess, pickle\n"
            "subprocess.run('echo unsafe', shell=True)\n"
            "pickle.loads(data)\n"
        )
        self.assertEqual({"SEC002", "SEC003"}, {finding.rule for finding in findings})

    def test_syntax_errors_are_reported(self):
        finding = analyze_source("def broken(:\n", "broken.py")[0]
        self.assertEqual("PY001", finding.rule)
        self.assertEqual(1, finding.line)
        self.assertIn("invalid Python syntax", finding.message)

    def test_clean_source_has_no_findings(self):
        self.assertEqual([], analyze_source("value = 1\nif value is None:\n    pass\n"))

    def test_source_is_parsed_without_execution_and_line_length_is_reported(self):
        source = 'raise RuntimeError("this source is only parsed")\n' + "value = " + ("x" * 130)
        findings = analyze_source(source, "untrusted.py")
        self.assertEqual(["COR004", "STY002"], [finding.rule for finding in findings])
        self.assertEqual((2, 121), (findings[1].line, findings[1].column))


if __name__ == "__main__":
    unittest.main()
