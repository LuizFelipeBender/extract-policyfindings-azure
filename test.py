from __future__ import annotations
from datetime import datetime, timedelta, timezone
import os
import re
import time
import math
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, Iterable, Optional, Tuple, List

import pandas as pd
import requests  # NEW

from azure.identity import DefaultAzureCredential
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.policyinsights import PolicyInsightsClient
from azure.mgmt.policyinsights.models import QueryOptions
from azure.mgmt.resource.policy import PolicyClient
from azure.mgmt.authorization import AuthorizationManagementClient  # NEW
from azure.core.exceptions import HttpResponseError, ServiceRequestError

# ================== Config ==================

TIME_TO = datetime.now(timezone.utc)
TIME_FROM = TIME_TO - timedelta(days=30)

# Filtros opcionais
RESOURCE_TYPE_FILTER: Optional[str] = None  # ex.: "Microsoft.Resources/subscriptions/resourceGroups" ou None
POLICY_DEFINITION_ID: Optional[str] = None  # ex.: "/providers/Microsoft.Authorization/policyDefinitions/deny-vm-without-nic"

# Se quiser processar apenas um subconjunto de assinaturas, preencha uma lista:
SUBSCRIPTION_ID_ALLOWLIST: Optional[List[str]] = None  # ex.: ["00000000-0000-0000-0000-000000000000", ...]

# Concurrency (ajuste conforme seu limite de API/tenant)
MAX_WORKERS = 8  # 4-12 costuma ser seguro. Aumente com cautela

# Output
OUTPUT_DIR = "."
STAMP = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
CSV_SUMMARY = os.path.join(OUTPUT_DIR, f"policy_summary_all_subs_{STAMP}.csv")
CSV_NONCOMP = os.path.join(OUTPUT_DIR, f"noncompliant_resources_all_subs_{STAMP}.csv")
CSV_RES_OWNERS = os.path.join(OUTPUT_DIR, f"resource_owners_all_subs_{STAMP}.csv")  # NEW

# Logs
PRINT_LIMIT_PER_SUB = 30

# ================== Helpers ==================
_lock_print = threading.Lock()

def log(msg: str) -> None:
    with _lock_print:
        print(msg, flush=True)


def parse_rg_name(resource_id: str) -> str:
    if not resource_id:
        return ""
    m = re.search(r"/resourceGroups/([^/]+)", resource_id, re.IGNORECASE)
    return m.group(1) if m else ""


def parse_resource_name(resource_id: str) -> str:
    """Extrai o último segmento do resourceId como 'nome do recurso' (heurística simples)."""
    if not resource_id:
        return ""
    parts = [p for p in resource_id.strip("/").split("/") if p]
    return parts[-1] if parts else ""


def get_assignments_map(pol_client: PolicyClient) -> Dict[str, Any]:
    # Escopo: assinatura atual
    d: Dict[str, Any] = {}
    for a in pol_client.policy_assignments.list():
        if not getattr(a, "id", None):
            continue
        d[a.id] = a
    return d


def get_definitions_map(pol_client: PolicyClient) -> Dict[str, Any]:
    # Definitions da assinatura + built-ins
    m: Dict[str, Any] = {}
    try:
        for d in pol_client.policy_definitions.list():
            if getattr(d, "id", None):
                m[d.id] = d
    except Exception:
        pass
    try:
        for d in pol_client.policy_definitions.list_builtin_definitions():
            if getattr(d, "id", None):
                m[d.id] = d
    except Exception:
        pass
    return m


def make_pi_client(credential, subscription_id: str) -> PolicyInsightsClient:
    # Compatível com versões antigas/novas do SDK
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

# -------------- Retry wrapper --------------

def _retry(callable_fn, *args, **kwargs):
    """Retry exponencial simples para chamadas do SDK."""
    max_tries = 6
    base = 0.8
    for attempt in range(1, max_tries + 1):
        try:
            return callable_fn(*args, **kwargs)
        except (HttpResponseError, ServiceRequestError, TimeoutError) as e:
            if attempt >= max_tries:
                raise
            sleep_s = base * (2 ** (attempt - 1)) + (0.1 * attempt)
            log(f"[retry] tentativa {attempt}/{max_tries} após erro: {e}. Aguardando {sleep_s:.1f}s...")
            time.sleep(sleep_s)


def pi_query_for_subscription(pi_client: PolicyInsightsClient, subscription_id: str,
                              *, policy_states_resource: str = "latest", **qkwargs):
    """Tenta variações (subscription/scope; nomeado/posicional) usando QueryOptions, com retry."""
    opts = build_query_options(**qkwargs)
    scope = f"/subscriptions/{subscription_id}"

    # 1) subscription_id nomeado
    try:
        return _retry(
            pi_client.policy_states.list_query_results_for_subscription,
            subscription_id=subscription_id,
            policy_states_resource=policy_states_resource,
            query_options=opts,
        )
    except TypeError:
        pass
    # 2) subscription_id posicional
    try:
        return _retry(
            pi_client.policy_states.list_query_results_for_subscription,
            policy_states_resource,
            subscription_id,
            query_options=opts,
        )
    except TypeError:
        pass
    # 3) scope nomeado
    try:
        return _retry(
            pi_client.policy_states.list_query_results_for_scope,
            scope=scope,
            policy_states_resource=policy_states_resource,
            query_options=opts,
        )
    except TypeError:
        pass
    # 4) scope posicional
    return _retry(
        pi_client.policy_states.list_query_results_for_scope,
        policy_states_resource,
        scope,
        query_options=opts,
    )


def iter_policy_states(pager: Iterable[Any]):
    """Itera por páginas/itens do Policy Insights (compatível com diferentes versões)."""
    for page in pager:
        vals = getattr(page, "value", None)
        if isinstance(vals, list):
            for row in vals:
                yield row
        else:
            # Algumas versões já retornam direto
            yield page


# ---- extração robusta de campos (case-insensitive + aliases) ----

def to_dict(row: Any) -> Dict[str, Any]:
    if hasattr(row, "as_dict"):
        try:
            return row.as_dict()  # type: ignore
        except Exception:
            pass
    d: Dict[str, Any] = {}
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


def pick(d: Dict[str, Any], *names: str, default=None):
    if not isinstance(d, dict):
        return default
    aliases: List[str] = []
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
            snake = re.sub(r"(?<!^)(?=[A-Z])", "_", n).lower()
            aliases.append(snake)
    for key in list(d.keys()):
        for a in aliases:
            if key == a or key.lower() == a.lower():
                return d[key]
    return default


# ================== RBAC Owner (via Graph) ==================  NEW

# Cache simples para reduzir chamadas ao Graph
_graph_user_cache: Dict[str, Optional[str]] = {}  # principal_id -> email/UPN (ou None)

def _graph_token(credential: DefaultAzureCredential) -> str:
    """Obtém token para Microsoft Graph."""
    tok = credential.get_token("https://graph.microsoft.com/.default")
    return tok.token

def _graph_get_user_email(credential: DefaultAzureCredential, principal_id: str) -> Optional[str]:
    """Resolve um objectId (principal_id) para e-mail/UPN via Microsoft Graph."""
    if not principal_id:
        return None
    if principal_id in _graph_user_cache:
        return _graph_user_cache[principal_id]
    try:
        token = _graph_token(credential)
        # Tenta usuário
        url = f"https://graph.microsoft.com/v1.0/users/{principal_id}?$select=mail,userPrincipalName"
        resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            email = data.get("mail") or data.get("userPrincipalName")
            _graph_user_cache[principal_id] = email
            return email
        # Pode ser um grupo/serviço. Tenta grupo para pelo menos retornar displayName (sem e-mail).
        url_g = f"https://graph.microsoft.com/v1.0/groups/{principal_id}?$select=mail,displayName"
        resp_g = requests.get(url_g, headers={"Authorization": f"Bearer {token}"}, timeout=15)
        if resp_g.status_code == 200:
            data = resp_g.json()
            email = data.get("mail") or data.get("displayName")
            _graph_user_cache[principal_id] = email
            return email
    except Exception as e:
        log(f"[WARN] Falha ao resolver principal {principal_id} no Graph: {e}")
    _graph_user_cache[principal_id] = None
    return None

def get_subscription_owner_emails(credential: DefaultAzureCredential, subscription_id: str) -> List[str]:
    """
    Retorna lista de e-mails/UPNs dos PRINCIPAIS com papel RBAC 'Owner' no escopo exato da assinatura.
    """
    owner_emails: List[str] = []
    try:
        auth_client = AuthorizationManagementClient(credential, subscription_id)
        scope = f"/subscriptions/{subscription_id}"

        # Descobre o roleDefinitionId para "Owner"
        owner_role_def_id = None
        for rd in auth_client.role_definitions.list(scope, filter="roleName eq 'Owner'"):
            owner_role_def_id = rd.id
            break
        # Fallback para o GUID well-known do Owner
        if not owner_role_def_id:
            owner_role_def_id = f"{scope}/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"

        # Lista role assignments no escopo
        ras = auth_client.role_assignments.list_for_scope(scope)
        principals: List[str] = []
        for ra in ras:
            try:
                if (getattr(ra, "role_definition_id", "") or "").lower() == (owner_role_def_id or "").lower():
                    # Garante que o escopo seja exatamente a assinatura (evitar heranças em RG/resources)
                    if (getattr(ra, "scope", "") or "").strip().lower() == scope.lower():
                        pid = getattr(ra, "principal_id", None)
                        if pid:
                            principals.append(pid)
            except Exception:
                continue

        # Resolve e-mails/UPNs via Graph
        emails = []
        for pid in set(principals):
            mail = _graph_get_user_email(credential, pid)
            if mail:
                emails.append(mail)
        # Ordena para determinismo
        owner_emails = sorted(set(emails))
    except Exception as e:
        log(f"[WARN] Falha ao obter Owners da assinatura {subscription_id}: {e}")
    return owner_emails


# ================== Core ==================

def process_subscription(sub, credential) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    sub_id = sub.subscription_id
    sub_name = getattr(sub, "display_name", None) or getattr(sub, "subscription_policies", None) or sub_id

    pi_client = make_pi_client(credential, sub_id)
    pol_client = PolicyClient(credential, sub_id)

    # Mapas para resoluções de nomes
    assignments_map = get_assignments_map(pol_client)
    definitions_map = get_definitions_map(pol_client)

    # Lookups case-insensitive
    assignments_map_lc = { (a.id or "").lower(): a for a in assignments_map.values() }
    definitions_map_lc = { (d.id or "").lower(): d for d in definitions_map.values() }

    # NEW: resolve Owners RBAC da assinatura (1x por assinatura)
    owner_emails = get_subscription_owner_emails(credential, sub_id)

    summary_rows: List[Dict[str, Any]] = []
    noncompliant_rows: List[Dict[str, Any]] = []
    resource_owner_rows: List[Dict[str, Any]] = []  # NEW

    # ---------- 1) Resumo por assignment ----------
    try:
        _filter_parts = []
        if RESOURCE_TYPE_FILTER:
            _filter_parts.append(f"ResourceType eq '{RESOURCE_TYPE_FILTER}'")
        if POLICY_DEFINITION_ID:
            _filter_parts.append(f"PolicyDefinitionId eq '{POLICY_DEFINITION_ID}'")
        _filter = " and ".join(_filter_parts) if _filter_parts else None

        pager = pi_query_for_subscription(
            pi_client, sub_id,
            policy_states_resource="latest",
            from_property=TIME_FROM,
            to=TIME_TO,
            top=2000,
            filter=_filter,
            apply="groupby((PolicyAssignmentId, IsCompliant), aggregate($count as Count))",
        )

        counts_by_assignment: Dict[str, Dict[str, int]] = {}
        for row in iter_policy_states(pager):
            d = to_dict(row)
            a_id_lc = (pick(d, "PolicyAssignmentId", "policy_assignment_id") or "").lower()
            is_comp = str(pick(d, "IsCompliant", "is_compliant", default=False)).lower()
            cnt = pick(d, "Count", "count", default=0)
            try:
                cnt = int(cnt)
            except Exception:
                cnt = 0
            if not a_id_lc:
                continue
            bucket = counts_by_assignment.setdefault(a_id_lc, {"true": 0, "false": 0})
            bucket["true" if is_comp in ("true", "1") else "false"] += cnt

        printed = 0
        log(f"\n=== Assinatura: {sub_name} ({sub_id}) ===")
        log("Resumo por Policy Assignment:")

        for a_id_lc, a_obj in assignments_map_lc.items():
            a_id = a_obj.id
            a_disp = getattr(a_obj, "display_name", None) or getattr(a_obj, "name", None) or a_id
            a_scope = getattr(a_obj, "scope", None)

            d_id = getattr(a_obj, "policy_definition_id", None)
            d_disp = None
            if d_id:
                d_obj = definitions_map_lc.get((d_id or "").lower())
                if d_obj:
                    d_disp = getattr(d_obj, "display_name", None) or getattr(d_obj, "name", None)

            if POLICY_DEFINITION_ID and (not d_id or d_id.lower() != POLICY_DEFINITION_ID.lower()):
                continue

            buckets = counts_by_assignment.get(a_id_lc, {"true": 0, "false": 0})
            compliantCount = int(buckets.get("true", 0))
            nonCompliantCount = int(buckets.get("false", 0))
            totalResources = compliantCount + nonCompliantCount

            if nonCompliantCount > 0:
                status = "NonCompliant"
            elif totalResources > 0:
                status = "Compliant"
            else:
                status = "NoResources"

            summary_rows.append({
                "subscriptionId": sub_id,
                "subscriptionName": sub_name,
                "policyAssignmentName": a_disp,
                "policyAssignmentId": a_id,
                "policyAssignmentScope": a_scope,
                "policyDefinitionName": d_disp,
                "policyDefinitionId": d_id,
                "status": status,
                "totalResources": totalResources,
                "compliantCount": compliantCount,
                "nonCompliantCount": nonCompliantCount,
            })

            if printed < PRINT_LIMIT_PER_SUB:
                log(f"- {status} | total={totalResources} | nonComp={nonCompliantCount} | assignment={a_disp}")
                printed += 1

    except Exception as e:
        log(f"[WARN] Falha no resumo em {sub_id}: {e}")

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
            select=(
                "ResourceId, ResourceType, ResourceGroup, "
                "PolicyAssignmentId, PolicyAssignmentName, "
                "PolicyDefinitionId, PolicyDefinitionName, "
                "PolicySetDefinitionId, PolicySetDefinitionName, "
                "Timestamp"
            ),
            order_by="Timestamp desc",
        )

        printed = 0
        log("\nRecursos NÃO conformes (detalhe):")
        seen_resources: set[str] = set()  # NEW: para gerar o CSV de owners sem duplicar

        for row in iter_policy_states(pager):
            d = to_dict(row)
            res_id = pick(d, "ResourceId", "resource_id")
            a_id  = pick(d, "PolicyAssignmentId", "policy_assignment_id")
            d_id  = pick(d, "PolicyDefinitionId", "policy_definition_id")
            ps_id = pick(d, "PolicySetDefinitionId", "policy_set_definition_id")
            ts    = pick(d, "Timestamp", "timestamp")

            # Preferir os nomes do próprio resultado
            a_disp_api = pick(d, "PolicyAssignmentName", "policy_assignment_name")
            d_disp_api = pick(d, "PolicyDefinitionName", "policy_definition_name")
            ps_name_api = pick(d, "PolicySetDefinitionName", "policy_set_definition_name")

            # Fallbacks
            a_obj = assignments_map.get(a_id) or assignments_map_lc.get((a_id or "").lower())
            d_obj = definitions_map.get(d_id) or definitions_map_lc.get((d_id or "").lower())

            a_disp = a_disp_api or getattr(a_obj, "display_name", None) or getattr(a_obj, "name", None) or a_id
            d_disp = d_disp_api or getattr(d_obj, "display_name", None) or getattr(d_obj, "name", None) or d_id

            noncompliant_rows.append({
                "subscriptionId": sub_id,
                "subscriptionName": sub_name,
                "resourceId": res_id,
                "resourceGroup": parse_rg_name(res_id),
                "policyAssignmentId": a_id,
                "policyAssignmentName": a_disp,
                "policyDefinitionId": d_id,
                "policyDefinitionName": d_disp,                  # display name da policy
                "policyDefinitionDisplayName": d_disp,           # coluna explícita
                "policySetDefinitionId": ps_id,
                "policySetDefinitionName": ps_name_api,          # se for initiative
                "timestamp": ts,
            })

            # --- NEW: montar linha para CSV de owners (1 por recurso; de assin. atual) ---
            if res_id and res_id not in seen_resources:
                seen_resources.add(res_id)
                resource_owner_rows.append({
                    "subscriptionId": sub_id,
                    "subscriptionName": sub_name,
                    "resourceId": res_id,
                    "resourceName": parse_resource_name(res_id),
                    "resourceType": pick(d, "ResourceType", "resource_type"),
                    "ownerEmails": ";".join(owner_emails) if owner_emails else "",
                })

            if printed < PRINT_LIMIT_PER_SUB:
                log(f"- {res_id} | assignment={a_disp} | policy={d_disp} | initiative={ps_name_api} | at={ts}")
                printed += 1
        if printed == 0:
            log("- (nenhum item nos últimos 30 dias com esse filtro)")

    except Exception as e:
        log(f"[WARN] Falha ao listar não conformes em {sub_id}: {e}")

    return summary_rows, noncompliant_rows, resource_owner_rows

start_time = time.time()

def main():
    credential = DefaultAzureCredential()

    subs_client = SubscriptionClient(credential)
    all_subs = [s for s in subs_client.subscriptions.list()]

    # Filtra por estado e allowlist
    filtered_subs = []
    for s in all_subs:
        sid = s.subscription_id
        state = getattr(s, "state", None) or getattr(s, "subscription_policies", None)
        if SUBSCRIPTION_ID_ALLOWLIST and sid not in SUBSCRIPTION_ID_ALLOWLIST:
            continue
        # Inclui apenas assinaturas ativas quando disponível
        if state and str(state).lower() not in ("enabled", "active", "enabledstate"):
            continue
        filtered_subs.append(s)

    if not filtered_subs:
        log("[WARN] Nenhuma assinatura elegível encontrada.")
        return

    log(f"Total de assinaturas a processar: {len(filtered_subs)}")

    # Execução concorrente
    summary_rows_all: List[Dict[str, Any]] = []
    noncomp_rows_all: List[Dict[str, Any]] = []
    res_owner_rows_all: List[Dict[str, Any]] = []  # NEW

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_subscription, s, credential): s for s in filtered_subs}
        for fut in as_completed(futures):
            sub = futures[fut]
            try:
                srows, nrows, rrows = fut.result()
                summary_rows_all.extend(srows)
                noncomp_rows_all.extend(nrows)
                res_owner_rows_all.extend(rrows)
            except Exception as e:
                log(f"[ERROR] Assinatura {sub.subscription_id}: {e}")

    # ================== Export (CSV) ==================
    df_summary = pd.DataFrame(summary_rows_all)
    df_noncomp = pd.DataFrame(noncomp_rows_all)
    df_resown  = pd.DataFrame(res_owner_rows_all)  # NEW

    if not df_summary.empty:
        df_summary.sort_values(
            by=["subscriptionName", "status", "policyAssignmentName"],
            ascending=[True, True, True],
            inplace=True,
        )
    if not df_noncomp.empty:
        df_noncomp.sort_values(
            by=["subscriptionName", "resourceGroup", "policyAssignmentName", "timestamp"],
            inplace=True,
        )
    if not df_resown.empty:
        # Remove duplicatas caso o mesmo recurso apareça em múltiplas linhas (por múltiplas policies)
        df_resown.drop_duplicates(subset=["resourceId"], inplace=True)
        df_resown.sort_values(
            by=["subscriptionName", "resourceType", "resourceName"],
            inplace=True,
        )

    # Reordena colunas do summary
    summary_cols = [
        "subscriptionId", "subscriptionName",
        "policyAssignmentName", "policyAssignmentId", "policyAssignmentScope",
        "policyDefinitionName", "policyDefinitionId",
        "status", "totalResources", "compliantCount", "nonCompliantCount",
    ]
    df_summary = df_summary.reindex(columns=summary_cols)

    # Reordena colunas do detalhe (inclui initiative quando houver)
    noncomp_cols = [
        "subscriptionId", "subscriptionName", "resourceId", "resourceGroup",
        "policyAssignmentId", "policyAssignmentName",
        "policyDefinitionId", "policyDefinitionName", "policyDefinitionDisplayName",
        "policySetDefinitionId", "policySetDefinitionName",
        "timestamp",
    ]
    df_noncomp = df_noncomp.reindex(columns=noncomp_cols)

    # NEW: colunas do CSV de recurso + owners
    resown_cols = [
        "subscriptionId", "subscriptionName",
        "resourceId", "resourceName", "resourceType",
        "ownerEmails",
    ]
    df_resown = df_resown.reindex(columns=resown_cols)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    df_summary.to_csv(CSV_SUMMARY, index=False, encoding="utf-8")
    df_noncomp.to_csv(CSV_NONCOMP, index=False, encoding="utf-8")
    df_resown.to_csv(CSV_RES_OWNERS, index=False, encoding="utf-8")  # NEW

    log("\nArquivos gerados:")
    log(f"- {CSV_SUMMARY}")
    log(f"- {CSV_NONCOMP}")
    log(f"- {CSV_RES_OWNERS}")  # NEW


if __name__ == "__main__":
    main()
elapsed = time.time() - start_time
minutes, seconds = divmod(elapsed, 60)
print(f"\nTempo total de execução: {int(minutes)}m {seconds:.2f}s")
