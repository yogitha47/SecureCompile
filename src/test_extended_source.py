"""Quick tests for source-level rules added to SecureCompile."""
import unittest
from source_analyzer import analyze_source


class ExtendedSourceRuleTests(unittest.TestCase):
    def rule_ids(self, source):
        return {finding["rule_id"] for finding in analyze_source(source)}

    def test_scalar_used_as_array(self):
        self.assertIn("SC-MEM-005", self.rule_ids("int scores; scores[0] = 2;"))

    def test_free_without_visible_allocation(self):
        self.assertIn("SC-MEM-006", self.rule_ids("int *ptr; free(ptr);"))

    def test_null_pointer_dereference(self):
        self.assertIn("SC-MEM-007", self.rule_ids("int *ptr = NULL; *ptr = 5;"))

    def test_double_free(self):
        self.assertIn("SC-MEM-008", self.rule_ids("int *p = malloc(8); free(p); free(p);"))

    def test_use_after_free(self):
        self.assertIn("SC-MEM-009", self.rule_ids("int *p = malloc(8); free(p); *p = 1;"))

    def test_possible_leak(self):
        self.assertIn("SC-MEM-010", self.rule_ids("void f(void) { int *p = malloc(8); }"))

    def test_unclosed_preprocessor(self):
        self.assertIn("SC-PP-001", self.rule_ids("#ifdef FEATURE\nint x;"))

    def test_unmatched_brace(self):
        self.assertIn("SC-SYN-001", self.rule_ids("int main(void) { return 0;"))

    def test_possible_integer_overflow(self):
        self.assertIn("SC-ARITH-003", self.rule_ids("int x = INT_MAX + 1;"))

    def test_switch_fallthrough(self):
        source = "switch (x) { case 1: x = 2; case 2: x = 3; break; }"
        self.assertIn("SC-LOGIC-004", self.rule_ids(source))

    def test_unreachable_after_return(self):
        self.assertIn("SC-LOGIC-003", self.rule_ids("int f(void) {\n return 0;\n int x = 1;\n}"))

    def test_safe_array_declaration_not_scalar_rule(self):
        self.assertNotIn("SC-MEM-005", self.rule_ids("int scores[6]; scores[0] = 2;"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
