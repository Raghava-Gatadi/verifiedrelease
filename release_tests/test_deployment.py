"""A rejected verification must never reach Docker or create an approved manifest."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts/release'))
import deploy
from verify import VerificationError


class DeploymentTests(unittest.TestCase):
    def test_denied_artifact_never_invokes_deployment(self):
        for stage in ['SIGNATURE', 'PROVENANCE', 'ATTESTATION', 'POLICY']:
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                previous = Path.cwd()
                try:
                    os.chdir(temporary)
                    with patch.object(sys, 'argv', ['deploy.py', '--image', 'example.test/app@sha256:' + 'a' * 64, '--commit', 'b' * 40]), \
                            patch('deploy.read_json', return_value={}), \
                            patch('deploy.production_flags', return_value=[]), \
                            patch('deploy.verify', side_effect=VerificationError(stage, 'rejected test artifact')), \
                            patch('deploy.subprocess.run') as process:
                        with self.assertRaises(SystemExit):
                            deploy.main()
                        process.assert_not_called()
                    decision = json.loads(Path('artifacts/deployment/decision.json').read_text())
                    self.assertEqual(decision['decision'], 'deny')
                    self.assertEqual(decision['stage'], stage)
                    self.assertFalse(Path('artifacts/deployment/verified.compose.json').exists())
                finally:
                    os.chdir(previous)
