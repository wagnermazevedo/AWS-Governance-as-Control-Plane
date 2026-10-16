"""Testes offline do modo gravação (lib/mask.py) nos scripts 00, 01, 02 e 99.

Rodar: python3 -m unittest discover -s tests -v
"""

import glob
import io
import json
import os
import runpy
import stat
import sys
import tempfile
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib import LAB_PREFIXES, mask  # noqa: E402
from mask_helpers import TEST_KEY, isolated_streams, reset_mask  # noqa: E402
from test_control_plane import Runner, lab_org  # noqa: E402
from test_lab_setup import SCRIPT as LAB_SCRIPT, make_clients  # noqa: E402

REAL_ACCOUNTS = ("111111111111", "222222222222")


def captured(fn, *args):
    """Roda fn com stdout/stderr capturados e devolve (resultado, texto da tela)."""
    out = io.StringIO()
    with mock.patch.object(sys, "stdout", out), mock.patch.object(sys, "stderr", out):
        result = fn(*args)
    return result, out.getvalue()


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def run_dir(yaml_path):
    folder = os.path.dirname(yaml_path)
    return read(os.path.join(folder, "summary.md")), read(os.path.join(folder, "governance_scan_export.csv"))


def real_ou_ids(org):
    return list(org.ous)


class MaskTestCase(unittest.TestCase):
    def setUp(self):
        reset_mask()
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop(mask.ENV_FLAG, None)

    def tearDown(self):
        reset_mask()


class ScanMasking(MaskTestCase):
    def test_masked_by_default_on_console_summary_and_csv(self):
        org = lab_org()
        (scan_yaml, export), console = captured(Runner(org).scan)
        summary, csv_text = run_dir(scan_yaml)

        for screen in (console, summary, csv_text):
            self.assertNotIn("loose-account", screen)
            for account in REAL_ACCOUNTS:
                self.assertNotIn(account, screen)
            for ou_id in real_ou_ids(org):
                self.assertNotIn(ou_id, screen)
            self.assertIn("SCP-Lab", screen)
        self.assertIn("nome-", console)
        self.assertIn("SCP-Lab-Exception", summary)
        self.assertNotIn("r-ab12", csv_text)

        # O YAML continua real: é a entrada do plan.
        raw = read(scan_yaml)
        self.assertIn("loose-account", raw)
        self.assertIn("222222222222", raw)
        self.assertEqual(export["metadata"]["callerAccountId"], "111111111111")
        json_raw = read(scan_yaml.replace(".yaml", ".json"))
        self.assertIn("loose-account", json_raw)

    def test_plan_and_remediate_still_work_with_real_values(self):
        org = lab_org()
        runner = Runner(org)
        (scan_yaml, _), _ = captured(runner.scan)
        (plan_path, plan), plan_console = captured(runner.plan, scan_yaml)
        self.assertNotIn("loose-account", plan_console)
        self.assertIn("SCP-Lab", plan_console)
        self.assertIn("loose-account", read(plan_path))

        (code, results), console = captured(runner.remediate, plan_path, "apply")
        self.assertEqual(code, 0, results)
        lab_id = [i for i, o in org.ous.items() if o["Name"] == "SCP-Lab"][0]
        self.assertEqual({t for _, t in org.attachments}, {lab_id})

        policy_ids = list(org.policies)
        self.assertTrue(policy_ids)
        rem_json = max(glob.glob(os.path.join(runner.tmp, "rem", "*", "governance_remediation_results.json")),
                       key=os.path.getmtime)
        rem_csv = read(rem_json.replace(".json", ".csv"))
        rem_summary = read(os.path.join(os.path.dirname(rem_json), "summary.md"))
        for screen in (console, rem_csv, rem_summary):
            self.assertNotIn(lab_id, screen)
            self.assertNotIn("r-ab12", screen)
            for pid in policy_ids:
                self.assertNotIn(pid, screen)
            self.assertIn("scp-gov-baseline", screen)
        self.assertIn(lab_id, read(rem_json))
        self.assertTrue(any(pid in read(rem_json) for pid in policy_ids))

    def test_no_mask_flag_shows_real_values_on_every_stage(self):
        org = lab_org()
        runner = Runner(org, extra_args=["--no-mask"])
        (scan_yaml, _), console = captured(runner.scan)
        summary, csv_text = run_dir(scan_yaml)
        self.assertFalse(mask.enabled())
        self.assertIn("loose-account", console)
        self.assertIn("111111111111", summary)
        self.assertIn("222222222222", csv_text)

        (plan_path, _), plan_console = captured(runner.plan, scan_yaml)
        self.assertIn("loose-account", plan_console)
        (code, _), rem_console = captured(runner.remediate, plan_path, "dry-run")
        self.assertEqual(code, 0)
        self.assertIn("r-ab12", rem_console)

    def test_env_flag_disables(self):
        os.environ[mask.ENV_FLAG] = "0"
        (scan_yaml, _), console = captured(Runner(lab_org()).scan)
        summary, _ = run_dir(scan_yaml)
        self.assertIn("loose-account", console)
        self.assertIn("111111111111", summary)

    def test_streams_are_restored(self):
        before = sys.stdout, sys.stderr
        captured(Runner(lab_org()).scan)
        self.assertEqual((sys.stdout, sys.stderr), before)


class LabSetupMasking(MaskTestCase):
    def run_lab(self, *args):
        clients = make_clients()
        clients["organizations"].responses["describe_policy"] = {
            "Policy": {"Content": json.dumps({"Statement": [{"Sid": "ProtectSecurityServices",
                                                             "Action": ["cloudtrail:StopLogging", "iam:X"]}]})}}
        state = os.path.join(tempfile.mkdtemp(), ".lab_state.json")
        with mock.patch("lib.aws.client", side_effect=lambda sess, svc: clients[svc]), \
             mock.patch("lib.aws.session", return_value=None), \
             mock.patch.object(sys, "argv", ["99", *args]), isolated_streams():
            ns = runpy.run_path(LAB_SCRIPT, run_name="not_main")
            ns["main"].__globals__["STATE_FILE"] = state
            _, console = captured(ns["main"])
        return console

    def test_lab_setup_masks_by_default(self):
        console = self.run_lab("--yes", "--move-account", "222222222222")
        for account in REAL_ACCOUNTS:
            self.assertNotIn(account, console)
        self.assertNotIn("ou-ab12-11111111", console)
        self.assertIn("SCP-Lab", console)

    def test_lab_setup_accepts_no_mask(self):
        console = self.run_lab("--yes", "--no-mask")
        self.assertIn("111111111111", console)

    def test_policy_id_is_hidden_on_drift(self):
        console = self.run_lab("--simulate-drift")
        self.assertIn("Drift aplicado em p-", console)
        self.assertNotIn("p-11111111", console)


class MaskBehavior(MaskTestCase):
    def setUp(self):
        super().setUp()
        with isolated_streams():
            mask.setup(argv=[], keep_prefixes=LAB_PREFIXES)

    def test_lab_names_stay_readable(self):
        mask.learn(["SCP-Lab", "SCP-Lab-Exception", "scp-gov-baseline", "tag-gov-required-tags",
                    "rcp-gov-s3-org-only", "Production", "wagner-prod"], kind="name")
        line = "Root/SCP-Lab Root/SCP-Lab-Exception scp-gov-baseline tag-gov-required-tags rcp-gov-s3-org-only"
        self.assertEqual(mask.mask_text(line), line)
        masked = mask.mask_text("Root/Production wagner-prod")
        self.assertNotIn("Production", masked)
        self.assertNotIn("wagner-prod", masked)

    def test_aliases_are_stable(self):
        line = "o-abcdef123456 ou-ab12-c3d4e5f6 r-ab12 999988887777 wagner@empresa.com.br"
        first = mask.mask_text(line)
        reset_mask()
        self.assertEqual(mask.mask_text(line), first)
        reset_mask(key=b"x" * 32)
        self.assertNotEqual(mask.mask_text(line), first)

    def test_key_file_is_created_private_and_reused(self):
        tmp = tempfile.mkdtemp()
        with mock.patch.object(mask, "__file__", os.path.join(tmp, "lib", "mask.py")):
            key = mask._load_key()
            path = os.path.join(tmp, "outputs", ".mask-key")
            self.assertTrue(os.path.exists(path))
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            self.assertEqual(mask._load_key(), key)

    def test_idempotent(self):
        line = ("Organização o-abcdef123456 · conta 999988887777 · OU ou-ab12-c3d4e5f6 · raiz r-ab12 · "
                "wagner@empresa.com.br · arn:aws:organizations::999988887777:ou/o-abcdef123456/ou-ab12-c3d4e5f6")
        once = mask.mask_text(line)
        self.assertEqual(mask.mask_text(once), once)
        for real in ("o-abcdef123456", "999988887777", "ou-ab12-c3d4e5f6", "r-ab12", "wagner@empresa.com.br"):
            self.assertNotIn(real, once)
        self.assertEqual(mask.mask_value({"a": [once]}), {"a": [once]})

    def test_policy_ids(self):
        from lib import learn_policy_ids
        learn_policy_ids("OK: política scp-gov-baseline criada (p-a1b2c3d4)", "p-FullAWSAccess")
        out = mask.mask_text("p-a1b2c3d4 p-FullAWSAccess")
        self.assertNotIn("p-a1b2c3d4", out)
        self.assertTrue(out.startswith("p-"))
        self.assertIn("p-FullAWSAccess", out)
        self.assertEqual(TEST_KEY, mask._KEY)


if __name__ == "__main__":
    unittest.main()
