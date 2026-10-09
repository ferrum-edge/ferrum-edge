"""CLI regressions for the scheduled benchmark history selector."""
import contextlib
import io
import unittest
from unittest.mock import patch

import latest_trusted_scheduled_runs as selector


class ScheduledRunCLITests(unittest.TestCase):
    def test_workflow_self_test_invocation_needs_no_live_arguments_or_network(self):
        with patch.object(selector.urllib.request, "urlopen") as request:
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(selector.main(["--self-test"]), 0)
        self.assertIn("self-test passed", output.getvalue())
        request.assert_not_called()

    def test_live_queries_still_require_both_identity_arguments(self):
        for args in [[], ["--workflow", "example.yml"], ["--current-sha", "a" * 40]]:
            with self.subTest(args=args), patch.object(selector.urllib.request, "urlopen") as request:
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as error:
                        selector.main(args)
                self.assertEqual(error.exception.code, 2)
                request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
