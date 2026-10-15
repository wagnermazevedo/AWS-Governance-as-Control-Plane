"""Testes offline do setup do laboratório (scripts/99_governance_lab_setup.py)."""

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

from recorder import Recorder  # noqa: E402

SCRIPT = os.path.join(REPO, "scripts", "99_governance_lab_setup.py")
LAB_OU, EXC_OU = "ou-ab12-11111111", "ou-ab12-22222222"


def make_clients():
    org = Recorder("organizations", {
        "describe_organization": {"Organization": {"Id": "o-abc123", "MasterAccountId": "111111111111"}},
        "list_roots": {"Roots": [{"Id": "r-ab12", "PolicyTypes": []}]},
        "list_parents": {"Parents": [{"Id": LAB_OU, "Type": "ORGANIZATIONAL_UNIT"}]},
        "list_policies": {"Policies": [{"Id": "p-11111111", "Name": "scp-gov-baseline"},
                                       {"Id": "p-22222222", "Name": "FullAWSAccess"}]},
        "list_tags_for_resource": {"Tags": [{"Key": "ManagedBy", "Value": "aws-governance-control-plane"}]},
        "list_targets_for_policy": {"Targets": []},
    })
    cfn = Recorder("cloudformation", {"describe_stacks": {"Stacks": [{
        "StackName": "governance-control-plane-lab", "CreationTime": "2026-10-15", "StackStatus": "CREATE_COMPLETE",
        "Outputs": [{"OutputKey": "ScpLabOUId", "OutputValue": LAB_OU},
                    {"OutputKey": "ScpLabExceptionOUId", "OutputValue": EXC_OU}]}]}})
    return {"organizations": org, "cloudformation": cfn}


class LabSetup(unittest.TestCase):
    def run_all(self, clients, *runs):
        state = os.path.join(tempfile.mkdtemp(), ".lab_state.json")
        for args in runs:
            with mock.patch("lib.aws.client", side_effect=lambda sess, svc: clients[svc]), \
                 mock.patch("lib.aws.session", return_value=None), \
                 mock.patch.object(sys, "argv", ["99", *args]):
                ns = runpy.run_path(SCRIPT, run_name="not_main")
                ns["main"].__globals__["STATE_FILE"] = state
                ns["main"]()
        return state

    def calls(self, clients):
        return [(svc, name, kw) for c in clients.values() for svc, name, kw in c.calls]

    def test_setup_move_and_destroy(self):
        clients = make_clients()
        state = self.run_all(clients, ["--yes", "--move-account", "222222222222"], ["--destroy"])
        names = [(s, n) for s, n, _ in self.calls(clients)]
        self.assertIn(("cloudformation", "create_stack"), names)
        moves = [kw for s, n, kw in self.calls(clients) if n == "move_account"]
        self.assertEqual(moves[0]["DestinationParentId"], LAB_OU)
        self.assertEqual(moves[1]["DestinationParentId"], "r-ab12", "destroy devolve a conta para a raiz")
        deleted = [kw["PolicyId"] for s, n, kw in self.calls(clients) if n == "delete_policy"]
        self.assertEqual(sorted(set(deleted)), ["p-11111111", "p-22222222"])
        self.assertIn(("cloudformation", "delete_stack"), names)
        self.assertNotIn(("organizations", "disable_policy_type"), names)
        self.assertFalse(os.path.exists(state))

    def test_destroy_skips_unmanaged_policies(self):
        clients = make_clients()
        clients["organizations"].responses["list_tags_for_resource"] = {"Tags": []}
        self.run_all(clients, ["--destroy"])
        names = [n for _, n, _ in self.calls(clients)]
        self.assertNotIn("detach_policy", names)
        self.assertNotIn("delete_policy", names)

    def test_setup_requires_confirmation(self):
        clients = make_clients()
        with mock.patch("builtins.input", return_value="nao"), self.assertRaises(SystemExit):
            self.run_all(clients, [])
        self.assertNotIn("create_stack", [n for _, n, _ in self.calls(clients)])


if __name__ == "__main__":
    unittest.main()
