"""Testes offline do ciclo scan -> plan -> remediate.

Rodar: python3 -m unittest discover -s tests -v
"""

import glob
import json
import os
import runpy
import sys
import tempfile
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fake_org import FakeOrg, FakeSts  # noqa: E402
from recorder import Recorder  # noqa: E402
from lib.io import load_yaml  # noqa: E402
from lib.policies import SIZE_LIMITS, check_size, compact, load_policy  # noqa: E402

RULES = os.path.join(REPO, "config", "governance_rules.yaml")


def lab_org(**kwargs):
    org = FakeOrg(**kwargs)
    org.add_ou("SCP-Lab", tags={"Environment": "lab"})
    org.add_ou("SCP-Lab-Exception", tags={"scp-exception": "Sandbox", "exception-owner": "cloud-platform-team"})
    org.add_ou("Production")  # fora dos alvos: nunca pode ser tocada
    org.add_account("222222222222", "loose-account")
    return org


def no_config():
    return Recorder("config", {"describe_configuration_recorder_status": {"ConfigurationRecordersStatus": []},
                               "describe_configuration_aggregators": {"ConfigurationAggregators": []}})


def no_control_tower():
    return Recorder("controltower", {"list_landing_zones": {"landingZones": []}})


class Runner:
    def __init__(self, org, config=None, controltower=None):
        self.org = org
        self.config = config or no_config()
        self.controltower = controltower or no_control_tower()
        self.tmp = tempfile.mkdtemp()

    def _run(self, script, *args):
        fakes = {"organizations": self.org, "sts": FakeSts(), "config": self.config, "controltower": self.controltower}
        with mock.patch("lib.aws.client", side_effect=lambda sess, svc: fakes[svc]), \
             mock.patch("lib.aws.session", return_value=None), \
             mock.patch.object(sys, "argv", [script, *args]):
            for name in ("00_governance_scan", "01_governance_plan", "02_governance_remediate"):
                sys.modules.pop(name, None)
            try:
                runpy.run_path(os.path.join(REPO, "scripts", script), run_name="__main__")
            except SystemExit as exc:
                return exc.code
        return 0

    def scan(self):
        out = os.path.join(self.tmp, "outputs")
        self._run("00_governance_scan.py", "--region", "us-east-1", "--output-dir", out)
        latest = max(glob.glob(os.path.join(out, "*", "governance_scan_export.yaml")), key=os.path.getmtime)
        return latest, load_yaml(latest)

    def plan(self, scan_yaml):
        plan_path = os.path.join(self.tmp, "remediation_plan.yaml")
        self._run("01_governance_plan.py", "--input-yaml", scan_yaml, "--rules", RULES, "--output-yaml", plan_path)
        return plan_path, load_yaml(plan_path)

    def remediate(self, plan_path, mode):
        out = os.path.join(self.tmp, "rem")
        code = self._run("02_governance_remediate.py", "--region", "us-east-1", "--yaml", plan_path,
                         "--mode", mode, "--output-dir", out)
        latest = max(glob.glob(os.path.join(out, "*", "governance_remediation_results.json")), key=os.path.getmtime)
        with open(latest, encoding="utf-8") as f:
            return code, json.load(f)


def by_control(items, control, name=None):
    return [i for i in items if i["control"] == control and (name is None or (i["resource"] or {}).get("name") == name)]


class PolicyFiles(unittest.TestCase):
    def test_policies_fit_size_limits(self):
        for f, t in [("policies/scp-gov-baseline.json", "SERVICE_CONTROL_POLICY"),
                     ("policies/scp-gov-region-guardrail.json", "SERVICE_CONTROL_POLICY"),
                     ("policies/tag-gov-required-tags.json", "TAG_POLICY")]:
            doc = load_policy(f)
            check_size(doc, t)
            self.assertLessEqual(len(compact(doc)), SIZE_LIMITS[t])

    def test_allowed_regions_param_is_rendered(self):
        doc = load_policy("policies/scp-gov-region-guardrail.json", {"allowed_regions": ["sa-east-1"]})
        cond = doc["Statement"][0]["Condition"]["StringNotEquals"]["aws:RequestedRegion"]
        self.assertEqual(cond, ["sa-east-1"])

    def test_region_guardrail_keeps_global_services(self):
        doc = load_policy("policies/scp-gov-region-guardrail.json")
        not_action = doc["Statement"][0]["NotAction"]
        for needed in ("iam:*", "sts:*", "organizations:*", "cloudfront:*", "route53:*", "support:*"):
            self.assertIn(needed, not_action)


class FullCycle(unittest.TestCase):
    def test_scan_is_read_only_and_flags_lab(self):
        org = lab_org()
        _, export = Runner(org).scan()
        self.assertEqual(org.write_calls, [])
        items = export["spec"]["items"]
        self.assertEqual(by_control(items, "GOV.1")[0]["status"], "PASS")
        self.assertEqual(by_control(items, "GOV.2")[0]["status"], "FAIL")
        for control in ("GOV.3", "GOV.4", "GOV.5"):
            lab = by_control(items, control, "SCP-Lab")[0]
            self.assertEqual(lab["status"], "FAIL")
            self.assertEqual(lab["verified_state"]["reason"], "POLICY_TYPE_DISABLED")
            self.assertEqual(by_control(items, control, "Production"), [])
        self.assertEqual(by_control(items, "GOV.6")[0]["resource"]["id"], "222222222222")

    def test_plan_decisions(self):
        runner = Runner(lab_org())
        scan_yaml, _ = runner.scan()
        _, plan = runner.plan(scan_yaml)
        items = plan["spec"]["items"]
        self.assertEqual(by_control(items, "GOV.2")[0]["decision"]["type"], "AUTO")
        self.assertEqual(by_control(items, "GOV.3", "SCP-Lab")[0]["decision"]["type"], "AUTO")
        self.assertEqual(by_control(items, "GOV.3", "SCP-Lab-Exception")[0]["decision"]["type"], "EXCEPTION")
        self.assertEqual(by_control(items, "GOV.6")[0]["decision"]["type"], "MANUAL")
        auto = [i["control"] for i in items if i["decision"]["type"] == "AUTO"]
        self.assertEqual(auto[0], "GOV.2", "GOV.2 precisa rodar antes das políticas")

    def test_exception_without_owner_goes_manual(self):
        from importlib import import_module
        decide = import_module("01_governance_plan").decide
        rules_doc = load_yaml(RULES)
        item = {"control": "GOV.3", "status": "FAIL", "exception": {"justification": "porque sim", "owner": None}}
        decision, reason, _, _ = decide(item, rules_doc["rules"], rules_doc["exception"])
        self.assertEqual(decision, "MANUAL")
        self.assertIn("sem dono", reason)

    def test_dry_run_changes_nothing(self):
        org = lab_org()
        runner = Runner(org)
        scan_yaml, _ = runner.scan()
        plan_path, _ = runner.plan(scan_yaml)
        code, results = runner.remediate(plan_path, "dry-run")
        self.assertEqual(code, 0)
        self.assertEqual(org.write_calls, [])
        summary = results["spec"]["summary"]
        self.assertEqual(summary["failed"], 0)
        self.assertEqual(summary["executed"], 4)  # GOV.2 + GOV.3/4/5 na SCP-Lab

    def test_apply_fixes_then_rescan_passes(self):
        org = lab_org()
        runner = Runner(org)
        scan_yaml, _ = runner.scan()
        plan_path, _ = runner.plan(scan_yaml)
        code, results = runner.remediate(plan_path, "apply")
        self.assertEqual(code, 0, results)
        self.assertTrue(all("VERIFIED" in r["message"] for r in results["spec"]["results"]
                            if r["decision"] == "AUTO" and r["control"] != "GOV.2"))
        targets = {t for _, t in org.attachments}
        lab_id = [i for i, o in org.ous.items() if o["Name"] == "SCP-Lab"][0]
        self.assertEqual(targets, {lab_id}, "só a OU SCP-Lab pode receber políticas")

        _, export = runner.scan()
        items = export["spec"]["items"]
        for control in ("GOV.2", "GOV.3", "GOV.4", "GOV.5"):
            lab = by_control(items, control, "SCP-Lab") or by_control(items, control)
            self.assertEqual(lab[0]["status"], "PASS", control)

    def test_drift_is_detected_and_restored(self):
        org = lab_org()
        runner = Runner(org)
        plan_path, _ = runner.plan(runner.scan()[0])
        runner.remediate(plan_path, "apply")

        pid = [p for p, v in org.policies.items() if v["summary"]["Name"] == "scp-gov-baseline"][0]
        doc = json.loads(org.policies[pid]["content"])
        doc["Statement"][1]["Action"] = [a for a in doc["Statement"][1]["Action"] if not a.startswith("cloudtrail:")]
        org.policies[pid]["content"] = json.dumps(doc)

        scan_yaml, export = runner.scan()
        lab = by_control(export["spec"]["items"], "GOV.3", "SCP-Lab")[0]
        self.assertEqual(lab["verified_state"]["reason"], "CONTENT_DRIFT")
        plan_path, _ = runner.plan(scan_yaml)
        code, _ = runner.remediate(plan_path, "apply")
        self.assertEqual(code, 0)
        self.assertIn("cloudtrail:StopLogging", org.policies[pid]["content"])

    def test_refuses_unmanaged_policy_with_same_name(self):
        org = lab_org(scp_enabled=True)
        org.create_policy(Name="scp-gov-baseline", Type="SERVICE_CONTROL_POLICY", Description="alheia",
                          Content='{"Version":"2012-10-17","Statement":[]}')
        org.calls.clear()
        runner = Runner(org)
        _, plan = runner.plan(runner.scan()[0])
        lab = by_control(plan["spec"]["items"], "GOV.3", "SCP-Lab")[0]
        self.assertEqual(lab["decision"]["type"], "MANUAL")

    def test_no_organization(self):
        org = FakeOrg(in_org=False)
        _, export = Runner(org).scan()
        items = export["spec"]["items"]
        self.assertEqual(by_control(items, "GOV.1")[0]["status"], "FAIL")
        self.assertTrue(all(i["status"] == "NOT_APPLICABLE" for i in items if i["control"] != "GOV.1"))


if __name__ == "__main__":
    unittest.main()


class NewPolicyControl(unittest.TestCase):
    """Adicionar uma política nova é só JSON em policies/ + uma regra no mapa (aqui, um GOV.9 com RCP)."""

    def test_new_rule_is_scanned_and_applied_without_code_changes(self):
        from remediate import REGISTRY
        from scanner.controls import evaluate

        rcp = {"Version": "2012-10-17", "Statement": [{
            "Sid": "DenyS3OutsideOrg", "Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "*",
            "Condition": {"StringNotEqualsIfExists": {"aws:PrincipalOrgID": "o-exemplo"},
                          "BoolIfExists": {"aws:PrincipalIsAWSService": "false"}}}]}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(rcp, f)
        rules_doc = load_yaml(RULES)
        params = {"policy_type": "RESOURCE_CONTROL_POLICY", "policy_name": "rcp-gov-s3-org-only",
                  "policy_file": f.name, "enable_type_if_needed": True}
        rules_doc["rules"]["GOV.9"] = {"title": "RCP: S3 só para identidades da organização", "decision": "AUTO",
                                       "action": "ensure_policy_attached", "params": params}

        org = lab_org()
        _, items = evaluate(org, rules_doc)
        lab = by_control(items, "GOV.9", "SCP-Lab")
        self.assertEqual(lab[0]["status"], "FAIL")
        self.assertEqual(len(by_control(items, "GOV.9")), 2)  # SCP-Lab e SCP-Lab-Exception

        outcome = REGISTRY["ensure_policy_attached"](org, lab[0], params, {}, False)
        self.assertTrue(outcome["ok"], outcome)
        self.assertIn("VERIFIED", outcome["message"])
        _, items = evaluate(org, rules_doc)
        self.assertEqual(by_control(items, "GOV.9", "SCP-Lab")[0]["status"], "PASS")
        os.remove(f.name)


class ConfigAndControlTower(unittest.TestCase):
    """GOV.7 (AWS Config na organização) e GOV.8 (Control Tower): só leitura, decisão MANUAL."""

    def test_default_lab_flags_config_and_skips_control_tower(self):
        runner = Runner(lab_org())
        _, export = runner.scan()
        items = export["spec"]["items"]
        self.assertEqual(by_control(items, "GOV.7")[0]["status"], "FAIL")
        self.assertEqual(by_control(items, "GOV.7")[0]["verified_state"]["reason"], "NO_TRUSTED_ACCESS")
        self.assertEqual(by_control(items, "GOV.8")[0]["status"], "NOT_APPLICABLE")
        _, plan = runner.plan(runner.scan()[0])
        self.assertEqual(by_control(plan["spec"]["items"], "GOV.7")[0]["decision"]["type"], "MANUAL")
        self.assertEqual(by_control(plan["spec"]["items"], "GOV.8")[0]["decision"]["type"], "NO_ACTION")
        self.assertEqual([c for c in runner.config.calls if not c[1].startswith("describe_")], [])

    def test_delegated_admin_counts_as_org_wide_config(self):
        org = lab_org()
        org.service_access = ["config-multiaccountsetup.amazonaws.com"]
        org.delegated = {"config.amazonaws.com": ["333333333333"]}
        _, export = Runner(org).scan()
        gov7 = by_control(export["spec"]["items"], "GOV.7")[0]
        self.assertEqual(gov7["status"], "PASS")
        self.assertEqual(gov7["verified_state"]["delegatedAdmins"], ["333333333333"])

    def test_control_tower_controls_per_target_ou(self):
        org = lab_org()
        lab_arn = [o["Arn"] for o in org.ous.values() if o["Name"] == "SCP-Lab"][0]

        class CT(Recorder):
            def list_enabled_controls(self, **kw):
                getattr(super(), "__getattr__")("list_enabled_controls")(**kw)
                if kw["targetIdentifier"] == lab_arn:
                    return {"enabledControls": [{"arn": "arn:x", "controlIdentifier": "arn:aws:controltower:us-east-1::control/AWS-GR_CLOUDTRAIL_CHANGE_PROHIBITED",
                                                 "driftStatusSummary": {"driftStatus": "IN_SYNC"}}]}
                return {"enabledControls": []}

        ct = CT("controltower", {"list_landing_zones": {"landingZones": [{"arn": "arn:aws:controltower:us-east-1:111111111111:landingzone/LZ1"}]}})
        _, export = Runner(org, controltower=ct).scan()
        gov8 = by_control(export["spec"]["items"], "GOV.8")
        self.assertEqual(by_control(gov8, "GOV.8", "SCP-Lab")[0]["status"], "PASS")
        self.assertEqual(by_control(gov8, "GOV.8", "SCP-Lab-Exception")[0]["status"], "FAIL")
        self.assertIn("exception", by_control(gov8, "GOV.8", "SCP-Lab-Exception")[0])

    def test_scp_quota_is_respected(self):
        from remediate import REGISTRY
        from scanner.controls import evaluate
        org = lab_org(scp_enabled=True)
        lab_id = [i for i, o in org.ous.items() if o["Name"] == "SCP-Lab"][0]
        for n in range(5):  # cinco SCPs já anexadas, como num ambiente com Control Tower
            org.policies[f"p-ct{n}"] = {"summary": {"Id": f"p-ct{n}", "Name": f"aws-guardrails-{n}", "Type": "SERVICE_CONTROL_POLICY"},
                                         "content": "{}"}
            org.attachments.add((f"p-ct{n}", lab_id))
        rules_doc = load_yaml(RULES)
        _, items = evaluate(org, rules_doc)
        item = by_control(items, "GOV.3", "SCP-Lab")[0]
        outcome = REGISTRY["ensure_policy_attached"](org, item, rules_doc["rules"]["GOV.3"]["params"], {}, False)
        self.assertFalse(outcome["ok"])
        self.assertIn("QUOTA", outcome["message"])
        self.assertNotIn(lab_id, {t for p, t in org.attachments if not p.startswith("p-ct")})
