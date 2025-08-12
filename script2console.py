# policy_insights_all_subs_csv_optimized.py
# -*- coding: utf-8 -*-
"""
Coleta resumo e detalhes de conformidade do Azure Policy Insights em *todas* as assinaturas
(ou em uma lista filtrada), otimizado para grande volume (~300 assinaturas) **com Modo Portal**
para bater com o widget "Resources by compliance state" do Azure Portal.

Destaques
- `totalResources` no summary (substitui `evaluatedCount`).
- CSV detalhado com display name de Policy/Initiative.
- **Portal Mode**: consolidação por `ResourceId` (non-compliant vence; mais recente desempata)
  para reproduzir a contagem do Portal — com CSV opcional.
- Execução concorrente (ThreadPoolExecutor), retries com backoff exponencial e logs de tempo.

Requisitos
  pip install azure-identity azure-mgmt-subscription azure-mgmt-policyinsights azure-mgmt-resource pandas
  Autenticação: DefaultAzureCredential (ex.: `az login`).
"""

from __future__ import annotations
from datetime import datetime, timedelta, timezone
import os
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, Iterable, Optional, Tuple, List

import pandas as pd

from azure.identity import DefaultAzureCredential
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.policyinsights import PolicyInsightsClient
from azure.mgmt.policyinsights.models import QueryOptions
from azure.mgmt.resource.policy import PolicyClient
from azure.core.exceptions import HttpResponseError, ServiceRequestError

# ================== Config ==================
# Janela temporal — alinhe com o Portal para bater números (ex.: 7 dias)
TIME_TO = datetime.now(timezone.utc)
TIME_FROM = TIME_TO - timedelta(days=30)

# Filtros opcionais
RESOURCE_TYPE_FILTER: Optional[str] = None  # ex.: "Microsoft.Resources/subscriptions/resourceGroups" ou None
POLICY_DEFINITION_ID: Optional[str] = None  # ex.: "/providers/Microsoft.Authorization/policyDefinitions/deny-vm-without-nic"

# Limitar a execução a um subconjunto de assinaturas
SUBSCRIPTION_ID_ALLOWLIST: Optional[List[str]] = None  # ex.: ["00000000-0000-0000-0000-000000000000"]

# Concurrency (ajuste conforme limites do tenant/API). 8–12 costuma ser bom.
MAX_WORKERS = 10

# Modo Portal — consolida por recurso para bater com "Resources by compliance state"
PORTAL_MODE = True
PORTAL_OUTPUT_CSV = True  # grava CSV consolidado (por sub e global)

# Output
OUTPUT_DIR = "."
STAMP = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
CSV_SUMMARY = os.path.join(OUTPUT_DIR, f"policy_summary_all_subs_{STAMP}.csv")
CSV_NONCOMP = os.path.join(OUTPUT_DIR, f"noncompliant_resources_all_subs_{STAMP}.csv")
CSV_PORTAL_GLOBAL = os.path.join(OUTPUT_DIR, f"resources_by_state_portal_mode_GLOBAL_{STAMP}.csv")

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


def get_assignments_map(pol_client: PolicyClient) -> Dict[str, Any]:
    d: Dict[str, Any] = {}
    for a in pol_client.policy_assignments.list():
        if getattr(a, "id", None):
            d[a.id] = a
    return d


def get_definitions_map(pol_client: PolicyClient) -> Dict[str, Any]:
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
    max_tries = 6
    base = 0.8
    for attempt in range(1, max_tries + 1):
        try:
            return callable_fn(*args, **kwargs)
        except (HttpResponseError, ServiceRequestError, TimeoutError) as e:
            if attempt >= max_tries:
                raise
            sleep_s = base * (2 ** (attempt - 1)) + (0.1 * attempt)
            log(f"[retry] tentativa {attempt}/{max_tries} após erro: {e}. aguardando {sleep_s:.1f}s...")
            time.sleep(sleep_s)


def pi_query_for_subscription(pi_client: PolicyInsightsClient, subscription_id: str,
                              *, policy_states_resource: str = "latest", **qkwargs):
    opts = build_query_options(**qkwargs)
    scope = f"/subscriptions/{subscription_id}"

    try:
        return _retry(
            pi_client.policy_states.list_query_results_for_subscription,
            subscription_id=subscription_id,
            policy_states_resource=policy_states_resource,
            query_options=opts,
        )
    except TypeError:
        pass
    try:
        return _retry(
            pi_client.policy_states.list_query_results_for_subscription,
            policy_states_resource,
            subscription_id,
            query_options=opts,
        )
    except TypeError:
        pass
    try:
        return _retry(
            pi_client.policy_states.list_query_results_for_scope,
            scope=scope,
            policy_states_resource=policy_states_resource,
            query_options=opts,
        )
    except TypeError:
        pass
    return _retry(
        pi_client.policy_states.list_query_results_for_scope,
        policy_states_resource,
        scope,
        query_options=opts,
    )


def iter_policy_states(pager: Iterable[Any]):
    for page in pager:
        vals = getattr(page, "value", None)
        if isinstance(vals, list):
            for row in vals:
                yield row
        else:
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
            import re as _re
            snake = _re.sub(r"(?<!^)(?=[A-Z])", "_", n).lower()
            aliases.append(snake)
    for key in list(d.keys()):
        for a in aliases:
            if key == a or key.lower() == a.lower():
                return d[key]
    return default


# ================== Core ==================
def process_subscription(sub, credential) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], pd.DataFrame]:
    sub_id = sub.subscription_id
    sub_name = getattr(sub, "display_name", None) or sub_id

    t0 = time.time()

    pi_client = make_pi_client(credential, sub_id)
    pol_client = PolicyClient(credential, sub_id)

    assignments_map = get_assignments_map(pol_client)
    definitions_map = get_definitions_map(pol_client)

    assignments_map_lc = { (a.id or "").lower(): a for a in assignments_map.values() }
    definitions_map_lc = { (d.id or "").lower(): d for d in definitions_map.values() }

    summary_rows: List[Dict[str, Any]] = []
    noncompliant_rows: List[Dict[str, Any]] = []

    log(f"\n=== Assinatura: {sub_name} ({sub_id}) ===")

    # ---------- 1) Resumo por assignment ----------
    try:
        _filter_parts: List[str] = []
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
        for row in iter_policy_states(pager):
            d = to_dict(row)
            res_id = pick(d, "ResourceId", "resource_id")
            a_id  = pick(d, "PolicyAssignmentId", "policy_assignment_id")
            d_id  = pick(d, "PolicyDefinitionId", "policy_definition_id")
            ps_id = pick(d, "PolicySetDefinitionId", "policy_set_definition_id")
            ts    = pick(d, "Timestamp", "timestamp")

            a_disp_api = pick(d, "PolicyAssignmentName", "policy_assignment_name")
            d_disp_api = pick(d, "PolicyDefinitionName", "policy_definition_name")
            ps_name_api = pick(d, "PolicySetDefinitionName", "policy_set_definition_name")

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
                "policyDefinitionName": d_disp,
                "policyDefinitionDisplayName": d_disp,
                "policySetDefinitionId": ps_id,
                "policySetDefinitionName": ps_name_api,
                "timestamp": ts,
            })

            if printed < PRINT_LIMIT_PER_SUB:
                log(f"- {res_id} | assignment={a_disp} | policy={d_disp} | initiative={ps_name_api} | at={ts}")
                printed += 1
        if printed == 0:
            log("- (nenhum item nos últimos 30 dias com esse filtro)")

    except Exception as e:
        log(f"[WARN] Falha ao listar não conformes em {sub_id}: {e}")

    # ---------- 3) Portal Mode: estados por recurso (True/False) ----------
    df_portal_sub = pd.DataFrame()
    if PORTAL_MODE:
        try:
            _filter_parts2: List[str] = []
            if RESOURCE_TYPE_FILTER:
                _filter_parts2.append(f"ResourceType eq '{RESOURCE_TYPE_FILTER}'")
            if POLICY_DEFINITION_ID:
                _filter_parts2.append(f"PolicyDefinitionId eq '{POLICY_DEFINITION_ID}'")
            _filter2 = " and ".join(_filter_parts2) if _filter_parts2 else None

            pager_states = pi_query_for_subscription(
                pi_client, sub_id,
                policy_states_resource="latest",
                from_property=TIME_FROM,
                to=TIME_TO,
                top=2000,
                filter=_filter2,
                select="ResourceId, IsCompliant, Timestamp",
                order_by="Timestamp desc",
            )

            rows_states: List[Dict[str, Any]] = []
            for row in iter_policy_states(pager_states):
                d = to_dict(row)
                rid = pick(d, "ResourceId", "resource_id")
                iscomp_raw = pick(d, "IsCompliant", "is_compliant", default=False)
                ts = pick(d, "Timestamp", "timestamp")
                iscomp = str(iscomp_raw).lower() == "true"
                rows_states.append({
                    "subscriptionId": sub_id,
                    "subscriptionName": sub_name,
                    "ResourceId": rid,
                    "IsCompliant": iscomp,
                    "Timestamp": ts,
                })

            df_portal_sub = pd.DataFrame(rows_states)
            if not df_portal_sub.empty:
                # False (non-compliant) primeiro; depois mais recente
                df_portal_sub.sort_values(by=["IsCompliant", "Timestamp"], ascending=[True, False], inplace=True)
                df_portal_sub = df_portal_sub.drop_duplicates(subset=["ResourceId"], keep="first")

                total_noncomp = (~df_portal_sub["IsCompliant"]).sum()
                total_comp = (df_portal_sub["IsCompliant"]).sum()
                log(f"[PortalMode] {sub_name}: compliant={int(total_comp)} | non-compliant={int(total_noncomp)} | total recs={len(df_portal_sub)}")
            else:
                log(f"[PortalMode] {sub_name}: sem estados no período")
        except Exception as e:
            log(f"[WARN] PortalMode falhou em {sub_id}: {e}")

    elapsed = time.time() - t0
    log(f"[{sub_id}] Finalizado em {elapsed:.2f}s")

    return summary_rows, noncompliant_rows, df_portal_sub


def main():
    start_all = time.time()
    credential = DefaultAzureCredential()

    subs_client = SubscriptionClient(credential)
    all_subs = [s for s in subs_client.subscriptions.list()]

    # Filtra por estado e allowlist
    filtered_subs: List[Any] = []
    for s in all_subs:
        sid = s.subscription_id
        if SUBSCRIPTION_ID_ALLOWLIST and sid not in SUBSCRIPTION_ID_ALLOWLIST:
            continue
        # Mantém todas; se quiser filtrar por estado (Enabled), ajuste aqui conforme seu tenant
        filtered_subs.append(s)

    if not filtered_subs:
        log("[WARN] Nenhuma assinatura elegível encontrada.")
        return

    log(f"Total de assinaturas a processar: {len(filtered_subs)}")

    summary_rows_all: List[Dict[str, Any]] = []
    noncomp_rows_all: List[Dict[str, Any]] = []
    portal_frames: List[pd.DataFrame] = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_subscription, s, credential): s for s in filtered_subs}
        for fut in as_completed(futures):
            sub = futures[fut]
            try:
                srows, nrows, df_portal_sub = fut.result()
                summary_rows_all.extend(srows)
                noncomp_rows_all.extend(nrows)
                if PORTAL_MODE and not df_portal_sub.empty:
                    portal_frames.append(df_portal_sub)
            except Exception as e:
                log(f"[ERROR] Assinatura {sub.subscription_id}: {e}")

    # ================== Export (CSV) ==================
    df_summary = pd.DataFrame(summary_rows_all)
    df_noncomp = pd.DataFrame(noncomp_rows_all)

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

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    df_summary.to_csv(CSV_SUMMARY, index=False, encoding="utf-8")
    df_noncomp.to_csv(CSV_NONCOMP, index=False, encoding="utf-8")

    log("\nArquivos gerados:")
    log(f"- {CSV_SUMMARY}")
    log(f"- {CSV_NONCOMP}")

    # ---------- Portal Mode (global) ----------
    if PORTAL_MODE and portal_frames:
        df_portal_global = pd.concat(portal_frames, ignore_index=True)
        # Dedup global por ResourceId (non-compliant vence; mais recente desempata)
        df_portal_global.sort_values(by=["IsCompliant", "Timestamp"], ascending=[True, False], inplace=True)
        df_portal_global = df_portal_global.drop_duplicates(subset=["ResourceId"], keep="first")

        if PORTAL_OUTPUT_CSV:
            df_portal_global.to_csv(CSV_PORTAL_GLOBAL, index=False, encoding="utf-8")
            log(f"- {CSV_PORTAL_GLOBAL}")

        total_noncomp = (~df_portal_global["IsCompliant"]).sum()
        total_comp = (df_portal_global["IsCompliant"]).sum()
        log(f"\n[PortalMode][GLOBAL] compliant={int(total_comp)} | non-compliant={int(total_noncomp)} | total recs={len(df_portal_global)}")
    elif PORTAL_MODE:
        log("[PortalMode] Nenhum estado consolidado para exportar.")

    elapsed_all = time.time() - start_all
    m, s = divmod(elapsed_all, 60)
    log(f"\nTempo total de execução: {int(m)}m {s:.2f}s")


if __name__ == "__main__":
    main()
