"""AWS Organizations em memória para testes offline.

Cada chamada é validada contra o modelo oficial do botocore (nome da operação,
parâmetros obrigatórios e tipos), então um parâmetro errado no código quebra
o teste do mesmo jeito que quebraria na AWS.
"""

import itertools

import botocore.session
from botocore.exceptions import ClientError
from botocore.validate import validate_parameters

_MODEL = botocore.session.get_session().get_service_model("organizations")
_REAL = botocore.session.get_session().create_client("organizations", region_name="us-east-1",
                                                     aws_access_key_id="x", aws_secret_access_key="x")
_ids = itertools.count(1)

PAGINATED_KEYS = {
    "list_roots": "Roots",
    "list_organizational_units_for_parent": "OrganizationalUnits",
    "list_parents": "Parents",
    "list_policies": "Policies",
    "list_policies_for_target": "Policies",
    "list_tags_for_resource": "Tags",
    "list_accounts_for_parent": "Accounts",
}


def _err(code, msg="fake"):
    return ClientError({"Error": {"Code": code, "Message": msg}}, "op")


class _Paginator:
    def __init__(self, fn):
        self.fn = fn

    def paginate(self, **kwargs):
        yield self.fn(**kwargs)


class FakeOrg:
    def __init__(self, in_org=True, feature_set="ALL", scp_enabled=False):
        self.in_org = in_org
        self.feature_set = feature_set
        self.root = {"Id": "r-ab12", "Name": "Root", "PolicyTypes": []}
        if scp_enabled:
            self.root["PolicyTypes"].append({"Type": "SERVICE_CONTROL_POLICY", "Status": "ENABLED"})
        self.parents = {}          # child_id -> parent_id
        self.ous = {}              # ou_id -> {Id, Name, Arn}
        self.accounts = {"111111111111": {"Id": "111111111111", "Name": "management"}}
        self.parents["111111111111"] = self.root["Id"]
        self.policies = {}         # policy_id -> {summary, content}
        self.attachments = set()   # (policy_id, target_id)
        self.tags = {}             # resource_id -> {k: v}
        self.calls = []

    # ---- infraestrutura -------------------------------------------------
    def _check(self, name, params):
        op = _MODEL.operation_model(_REAL.meta.method_to_api_mapping[name])
        if op.input_shape is not None:
            validate_parameters(params, op.input_shape)
        elif params:
            raise AssertionError(f"{name} não aceita parâmetros")
        self.calls.append((name, params))

    def get_paginator(self, name):
        assert _REAL.can_paginate(name), f"{name} não é paginável no boto3"
        fn = getattr(self, name)
        return _Paginator(fn)

    @property
    def write_calls(self):
        reads = ("describe_", "list_")
        return [c for c in self.calls if not c[0].startswith(reads)]

    # ---- helpers de cenário ---------------------------------------------
    def add_ou(self, name, parent=None, tags=None):
        ou_id = f"ou-ab12-{next(_ids):08d}"
        self.ous[ou_id] = {"Id": ou_id, "Name": name, "Arn": f"arn:aws:organizations::111111111111:ou/o-x/{ou_id}"}
        self.parents[ou_id] = parent or self.root["Id"]
        self.tags[ou_id] = dict(tags or {})
        return ou_id

    def add_account(self, account_id, name, parent=None):
        self.accounts[account_id] = {"Id": account_id, "Name": name}
        self.parents[account_id] = parent or self.root["Id"]

    # ---- leitura --------------------------------------------------------
    def describe_organization(self, **kw):
        self._check("describe_organization", kw)
        if not self.in_org:
            raise _err("AWSOrganizationsNotInUseException")
        return {"Organization": {"Id": "o-abc123", "FeatureSet": self.feature_set, "MasterAccountId": "111111111111"}}

    def list_roots(self, **kw):
        self._check("list_roots", kw)
        return {"Roots": [dict(self.root, PolicyTypes=[dict(p) for p in self.root["PolicyTypes"]])]}

    def list_organizational_units_for_parent(self, **kw):
        self._check("list_organizational_units_for_parent", kw)
        return {"OrganizationalUnits": [o for i, o in self.ous.items() if self.parents[i] == kw["ParentId"]]}

    def list_parents(self, **kw):
        self._check("list_parents", kw)
        parent = self.parents[kw["ChildId"]]
        return {"Parents": [{"Id": parent, "Type": "ROOT" if parent.startswith("r-") else "ORGANIZATIONAL_UNIT"}]}

    def list_policies(self, **kw):
        self._check("list_policies", kw)
        return {"Policies": [p["summary"] for p in self.policies.values() if p["summary"]["Type"] == kw["Filter"]]}

    def describe_policy(self, **kw):
        self._check("describe_policy", kw)
        p = self.policies[kw["PolicyId"]]
        return {"Policy": {"PolicySummary": p["summary"], "Content": p["content"]}}

    def list_policies_for_target(self, **kw):
        self._check("list_policies_for_target", kw)
        return {"Policies": [self.policies[pid]["summary"] for pid, tid in self.attachments
                             if tid == kw["TargetId"] and self.policies[pid]["summary"]["Type"] == kw["Filter"]]}

    def list_tags_for_resource(self, **kw):
        self._check("list_tags_for_resource", kw)
        return {"Tags": [{"Key": k, "Value": v} for k, v in self.tags.get(kw["ResourceId"], {}).items()]}

    def list_accounts_for_parent(self, **kw):
        self._check("list_accounts_for_parent", kw)
        return {"Accounts": [a for i, a in self.accounts.items() if self.parents[i] == kw["ParentId"]]}

    # ---- escrita --------------------------------------------------------
    def enable_policy_type(self, **kw):
        self._check("enable_policy_type", kw)
        self.root["PolicyTypes"].append({"Type": kw["PolicyType"], "Status": "ENABLED"})
        return {"Root": self.root}

    def create_policy(self, **kw):
        self._check("create_policy", kw)
        if any(p["summary"]["Name"] == kw["Name"] for p in self.policies.values()):
            raise _err("DuplicatePolicyException")
        pid = f"p-{next(_ids):08d}"
        summary = {"Id": pid, "Name": kw["Name"], "Type": kw["Type"], "AwsManaged": False}
        self.policies[pid] = {"summary": summary, "content": kw["Content"]}
        self.tags[pid] = {t["Key"]: t["Value"] for t in kw.get("Tags", [])}
        return {"Policy": {"PolicySummary": summary, "Content": kw["Content"]}}

    def update_policy(self, **kw):
        self._check("update_policy", kw)
        self.policies[kw["PolicyId"]]["content"] = kw["Content"]
        return {"Policy": {"PolicySummary": self.policies[kw["PolicyId"]]["summary"], "Content": kw["Content"]}}

    def attach_policy(self, **kw):
        self._check("attach_policy", kw)
        if (kw["PolicyId"], kw["TargetId"]) in self.attachments:
            raise _err("DuplicatePolicyAttachmentException")
        self.attachments.add((kw["PolicyId"], kw["TargetId"]))
        return {}


class FakeSts:
    def get_caller_identity(self):
        return {"Account": "111111111111", "Arn": "arn:aws:iam::111111111111:role/Admin"}
