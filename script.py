# policy_insights_all_subs_csv.py
from datetime import datetime, timedelta, timezone
import os, re
import pandas as pd

from azure.identity import DefaultAzureCredential
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.policyinsights import PolicyInsightsClient
from azure.mgmt.policyinsights.models import QueryOptions
from azure.mgmt.resource.policy import PolicyClient

# ================== Config ==================
TIME_TO = datetime.now(timezone.utc)
TIME_FROM = TIME_TO - timedelta(days=30)

# Filtros opcionais
RESOURCE_TYPE_FILTER = None  # ex.: "Microsoft.Resources/subscriptions/resourceGroups" ou None para todos
POLICY_DEFINITION_ID = None  # ex.: "/providers/Microsoft.Authorization/policyDefinitions/deny-vm-without-nic"

PRINT_LIMIT = 50
OUTPUT_DIR = "."
STAMP = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

CSV_SUMMARY = os.path.join(OUTPUT_DIR, f"policy_summary_all_subs_{STAMP}.csv")
CSV_NONCOMP = os.path.join(OUTPUT_DIR, f"noncompliant_resources_all_subs_{STAMP}.csv")

# ================== Helpers ==================
def parse_rg_name(resource_id: str) -> str:
    if not resource_id:
        return ""
    m = re.search(r"/resourceGroups/([^/]+)", resource_id, re.IGNORECASE)
    return m.group(1) if m else ""

def get_assignments_map(pol_client):
    # Lista assignments da assinatura (subscription scope e, em muitas versões, inclui escopos filhos)
    return {a.id: a for a in pol_client.policy_assignments.list()}

def get_definitions_map(pol_client):
    # Junta definitions da assinatura e as built-ins
    m = {}
    try:
        for d in pol_client.policy_definitions.list():
            m[d.id] = d
    except Exception:
        pass
    try:
        for d in pol_client.policy_definitions.list_builtin_definitions():
            m[d.id] = d
    except Exception:
        pass
    return m

def make_pi_client(credential, subscription_id):
    try:
        return PolicyInsightsClient(credential)
    except TypeError:
        return PolicyInsightsClient(credential, subscription_id)

def build_query_options(**kwargs) -> QueryOptions:
    return QueryOptions(
        from_property=kwargs.get("from_property"),
        to=kwargs.get("to"),
        top=kwargs.get("top"),
        filter=kwargs.get("filter"),
        apply=kwargs.get("apply"),
        select=kwargs.get("select"),
        order_by=kwargs.get("order_by"),
    )

def pi_query_for_subscription(pi_client, subscription_id, *, policy_states_resource="latest", **qkwargs):
    """Tenta variações (subscription/scope; nomeado/posicional) usando QueryOptions."""
    opts = build_query_options(**qkwargs)
    scope = f"/subscriptions/{subscription_id}"
    # 1) subscription_id nomeado
    try:
        return pi_client.policy_states.list_query_results_for_subscription(
            subscription_id=subscription_id, policy_states_resource=policy_states_resource, query_options=opts
        )
    except TypeError:
        pass
    # 2) subscription_id posicional
    try:
        return pi_client.policy_states.list_query_results_for_subscription(
            policy_states_resource, subscription_id, query_options=opts
        )
    except TypeError:
        pass
    # 3) scope nomeado
    try:
        return pi_client.policy_states.list_query_results_for_scope(
            scope=scope, policy_states_resource=policy_states_resource, query_options=opts
        )
    except TypeError:
        pass
    # 4) scope posicional
    return pi_client.policy_states.list_query_results_for_scope(
        policy_states_resource, scope, query_options=opts
    )

def iter_policy_states(pager):
    """Funciona com pager que retorna páginas (.value) ou itens diretos."""
    for page in pager:
        vals = getattr(page, "value", None)
        if isinstance(vals, list):
            for row in vals:
                yield row
        else:
            yield page

# ---- extração robusta de campos (case-insensitive + aliases) ----
def to_dict(row):
    if hasattr(row, "as_dict"):
        try:
            return row.as_dict()
        except Exception:
            pass
    d = {}
    props = getattr(row, "additional_properties", None)
    if isinstance(props, dict):
        d.update(props)
    for attr in dir(row):
        if attr.startswith("_"):
            continue
        try:
            val = getattr(row, attr)
        except Exception:
            continue
        if callable(val):
            continue
        if isinstance(val, (str, int, float, bool)) or "id" in attr.lower() or "time" in attr.lower():
            d[attr] = val
    return d

def pick(d: dict, *names, default=None):
    if not isinstance(d, dict):
        return default
    aliases = []
    for n in names:
        aliases.append(n)
        aliases.append(n.replace("_", ""))
        aliases.append(n.replace("_", "").lower())
        aliases.append(n.lower())
        if "_" in n:
            parts = n.split("_")
            camel = parts[0] + "".join(p.capitalize() for p in parts[1:])
            aliases += [camel, camel.lower()]
        else:
            snake = re.sub(r'(?<!^)(?=[A-Z])', '_', n).lower()
            aliases.append(snake)
    for key in d.keys():
        for a in aliases:
            if key == a or key.lower() == a.lower():
                return d[key]
    return default

# ================== Auth & Subscriptions ==================
credential = DefaultAzureCredential()
subs_client = SubscriptionClient(credential)
subscriptions = list(subs_client.subscriptions.list())

summary_rows, noncompliant_rows = [], []

for sub in subscriptions:
    sub_id = sub.subscription_id
    sub_name = getattr(sub, "display_name", None) or sub_id
    print(f"\n=== Assinatura: {sub_name} ({sub_id}) ===")

    pi_client = make_pi_client(credential, sub_id)
    pol_client = PolicyClient(credential, sub_id)

    assignments_map = get_assignments_map(pol_client)
    definitions_map = get_definitions_map(pol_client)

    # ---------- 1) Resumo por assignment (LEFT JOIN assignments x counts) ----------
    try:
        # Monta filtro do Policy Insights
        _filter_parts = []
        if RESOURCE_TYPE_FILTER:
            _filter_parts.append(f"ResourceType eq '{RESOURCE_TYPE_FILTER}'")
        if POLICY_DEFINITION_ID:
            _filter_parts.append(f"PolicyDefinitionId eq '{POLICY_DEFINITION_ID}'")
        _filter = " and ".join(_filter_parts) if _filter_parts else None

        # 1) Contadores por assignment x IsCompliant
        pager = pi_query_for_subscription(
            pi_client, sub_id,
            policy_states_resource="latest",
            from_property=TIME_FROM,
            to=TIME_TO,
            top=2000,
            filter=_filter,
            apply="groupby((PolicyAssignmentId, IsCompliant), aggregate($count as Count))"
        )

        counts_by_assignment = {}  # { assignmentId_lc: {"true": n, "false": n} }
        for row in iter_policy_states(pager):
            d = to_dict(row)
            a_id = (pick(d, "PolicyAssignmentId", "policy_assignment_id") or "").lower()
            is_comp = str(pick(d, "IsCompliant", "is_compliant", default=False)).lower()
            cnt = pick(d, "Count", "count", default=0)
            try:
                cnt = int(cnt)
            except Exception:
                cnt = 0
            if not a_id:
                continue
            bucket = counts_by_assignment.setdefault(a_id, {"true": 0, "false": 0})
            bucket["true" if is_comp in ("true", "1") else "false"] += cnt

        # 2) LEFT JOIN: todas as assignments aparecem (mesmo sem estados)
        assignments_map_lc = { (a.id or "").lower(): a for a in assignments_map.values() }
        definitions_map_lc = { (d.id or "").lower(): d for d in definitions_map.values() }

        print("\nResumo por Policy Assignment:")
        for a_id_lc, a_obj in assignments_map_lc.items():
            a_id = a_obj.id
            a_disp = getattr(a_obj, "display_name", None) or getattr(a_obj, "name", None) or a_id
            a_scope = getattr(a_obj, "scope", None)

            d_id = getattr(a_obj, "policy_definition_id", None)
            d_disp = None
            if d_id:
                d_obj = definitions_map_lc.get(d_id.lower())
                if d_obj:
                    d_disp = getattr(d_obj, "display_name", None) or getattr(d_obj, "name", None)

            # Se filtrar por definition, opcionalmente esconda assignments que não casem
            if POLICY_DEFINITION_ID and (not d_id or d_id.lower() != POLICY_DEFINITION_ID.lower()):
                continue

            buckets = counts_by_assignment.get(a_id_lc, {"true": 0, "false": 0})
            compliantCount = int(buckets.get("true", 0))
            nonCompliantCount = int(buckets.get("false", 0))
            evaluatedCount = compliantCount + nonCompliantCount

            if nonCompliantCount > 0:
                status = "NonCompliant"
            elif evaluatedCount > 0:
                status = "Compliant"
            else:
                status = "NoResources"  # 0 de 0

            summary_rows.append({
                "subscriptionId": sub_id,
                "subscriptionName": sub_name,
                "policyAssignmentName": a_disp,
                "policyAssignmentId": a_id,
                "policyAssignmentScope": a_scope,
                "policyDefinitionName": d_disp,
                "policyDefinitionId": d_id,
                "status": status,
                "evaluatedCount": evaluatedCount,
                "compliantCount": compliantCount,
                "nonCompliantCount": nonCompliantCount
            })

            print(f"- {status} | eval={evaluatedCount} | nonComp={nonCompliantCount} | assignment={a_disp}")
    except Exception as e:
        print(f"[WARN] Falha no resumo em {sub_id}: {e}")

    # ---------- 2) Recursos NÃO conformes (detalhe) ----------
    try:
        _filter_parts = ["IsCompliant eq false"]
        if RESOURCE_TYPE_FILTER:
            _filter_parts.append(f"ResourceType eq '{RESOURCE_TYPE_FILTER}'")
        if POLICY_DEFINITION_ID:
            _filter_parts.append(f"PolicyDefinitionId eq '{POLICY_DEFINITION_ID}'")
        _filter = " and ".join(_filter_parts)

        pager = pi_query_for_subscription(
            pi_client, sub_id,
            policy_states_resource="latest",
            from_property=TIME_FROM,
            to=TIME_TO,
            top=2000,
            filter=_filter,
            select="ResourceId, PolicyAssignmentId, PolicyDefinitionId, Timestamp"
        )

        print("\nRecursos NÃO conformes (detalhe):")
        printed = 0
        for row in iter_policy_states(pager):
            d = to_dict(row)
            res_id = pick(d, "ResourceId", "resource_id")
            a_id = pick(d, "PolicyAssignmentId", "policy_assignment_id")
            d_id = pick(d, "PolicyDefinitionId", "policy_definition_id")
            ts = pick(d, "Timestamp", "timestamp")

            a_obj = assignments_map.get(a_id)
            d_obj = definitions_map.get(d_id)
            a_disp = getattr(a_obj, "display_name", None) or getattr(a_obj, "name", None) or a_id
            d_disp = getattr(d_obj, "display_name", None) or d_id

            noncompliant_rows.append({
                "subscriptionId": sub_id,
                "subscriptionName": sub_name,
                "resourceId": res_id,
                "resourceGroup": parse_rg_name(res_id),
                "policyAssignmentId": a_id,
                "policyAssignmentName": a_disp,
                "policyDefinitionId": d_id,
                "policyDefinitionName": d_disp,
                "timestamp": ts
            })

            if printed < PRINT_LIMIT:
                print(f"- {res_id} | assignment={a_disp} | definition={d_disp} | at={ts}")
                printed += 1
        if printed == 0:
            print("- (nenhum item nos últimos 30 dias com esse filtro)")
    except Exception as e:
        print(f"[WARN] Falha ao listar não conformes em {sub_id}: {e}")

# ================== Export (CSV) ==================
df_summary = pd.DataFrame(summary_rows)
df_noncomp = pd.DataFrame(noncompliant_rows)

if not df_summary.empty:
    df_summary.sort_values(
        by=["subscriptionName", "status", "policyAssignmentName"],
        ascending=[True, True, True],
        inplace=True
    )
if not df_noncomp.empty:
    df_noncomp.sort_values(
        by=["subscriptionName", "resourceGroup", "policyAssignmentName", "timestamp"],
        inplace=True
    )

# Reordena colunas do summary para legibilidade
summary_cols = [
    "subscriptionId","subscriptionName",
    "policyAssignmentName","policyAssignmentId","policyAssignmentScope",
    "policyDefinitionName","policyDefinitionId",
    "status","evaluatedCount","compliantCount","nonCompliantCount"
]
df_summary = df_summary.reindex(columns=summary_cols)

df_summary.to_csv(CSV_SUMMARY, index=False, encoding="utf-8")
df_noncomp.to_csv(CSV_NONCOMP, index=False, encoding="utf-8")

print("\nArquivos gerados:")
print(f"- {CSV_SUMMARY}")
print(f"- {CSV_NONCOMP}")
