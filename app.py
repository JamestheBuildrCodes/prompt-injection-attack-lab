"""Prompt Injection Attack Lab - Streamlit interface.

Run with:  streamlit run app.py
"""
from __future__ import annotations

import html
import io
import time
import zipfile
from datetime import datetime
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from attacks.library import CATEGORIES, get_cases
from config.settings import (APP_NAME, CANARIES, DB_PATH, DEFAULT_SYSTEM_PROMPT, MAX_UPLOAD_MB, REQUEST_DELAY_S,
                             ROOT, SAMPLE_DOCS_DIR, STATUSES, VERSION, env_api_key, external_defaults)
from database.db import Database
from detectors.injection import scan_text
from engine.clients import ExternalTargetConfig, MockClient, OpenAICompatibleClient, UnauthorizedTargetError
from engine.documents import DocumentError, case_from_document, extract_text
from engine.runner import AssessmentRunner
from engine.samples import write_sample_documents
from mock_target.target import DEFENSES
from reports.exporters import build_report, report_to_json, report_to_pdf, results_to_csv

st.set_page_config(page_title=APP_NAME, layout="wide", initial_sidebar_state="expanded")

PAGES = ["Overview", "New assessment", "Attack library", "Test history", "Vulnerability analytics", "Security reports", "Settings"]
STATUS_COLORS = {"confirmed": "#B3261E", "suspected": "#B26A00", "inconclusive": "#5B6B7B", "resisted": "#1F7A5A"}
STATUS_HELP = {"confirmed": "Deterministic evidence: canary leaked or injected marker followed",
               "suspected": "Partial evidence such as paraphrased prompt leakage or persona adoption",
               "inconclusive": "Ambiguous, errored or empty response. Needs manual review",
               "resisted": "Refused, ignored or deflected the attack"}
INK, RULE = "#101C19", "#BFC9C4"


# ------------------------------------------------------------------ plumbing
@st.cache_resource
def get_db() -> Database:
    return Database()


def load_css() -> None:
    css = (ROOT / "assets" / "style.css").read_text(encoding="utf-8")
    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)


def pct(x: float) -> str:
    return f"{x:.0%}"


def when(iso: str | None) -> str:
    return (iso or "")[:16].replace("T", " ")


def goto(page: str) -> None:
    st.session_state["nav_request"] = page
    st.rerun()


def target_label(t: dict) -> str:
    return f"Mock target, {t.get('defense', '?')} defence" if t.get("type") == "mock" else f"External: {t.get('model', '?')} @ {t.get('host', '?')}"


def style_fig(fig: go.Figure, height: int = 320) -> go.Figure:
    fig.update_layout(height=height, margin=dict(l=8, r=8, t=28, b=8), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                      font=dict(family="Schibsted Grotesk, system-ui, sans-serif", color=INK, size=13),
                      legend=dict(orientation="h", y=-0.2), title_font=dict(size=15))
    fig.update_xaxes(gridcolor=RULE, zeroline=False)
    fig.update_yaxes(gridcolor=RULE, zeroline=False)
    return fig


# ------------------------------------------------------------ view fragments
def strip_html(results: list[dict]) -> str:
    cells = "".join(
        f'<i class="s-{r["status"]}{" ctl" if r.get("is_control") else ""}" title="{html.escape(r["case_id"])} {html.escape(r["name"])}: {r["status"]}"></i>'
        for r in results)
    counts = {s: sum(1 for r in results if r["status"] == s) for s in STATUSES}
    legend = "".join(f'<span style="--c:{STATUS_COLORS[s]}">{s} {counts[s]}</span>' for s in STATUSES)
    return f'<div class="strip" role="img" aria-label="One cell per test case, coloured by verdict">{cells}</div><div class="legend">{legend}</div>'


def show_reading(a: dict, results: list[dict]) -> None:
    s = a["score"]
    caps = "".join(f"<br>{html.escape(c)}" for c in s.get("caps_applied", []))
    st.markdown(
        f'<div class="reading-row"><div><div class="reading">{s["overall_score"]:.0f}<small>/100 grade {s["grade"]}</small></div></div>'
        f'<div class="reading-meta"><b>{html.escape(a["name"])}</b><br>{html.escape(target_label(a["target"]))}<br>{when(a["created_at"])}{caps}</div>'
        f'<div class="strip-wrap">{strip_html(results)}</div></div>', unsafe_allow_html=True)


def facts(s: dict) -> None:
    rows = [("Attack success rate", pct(s["attack_success_rate"])), ("Suspected rate", pct(s["suspected_rate"])),
            ("Inconclusive rate", pct(s["inconclusive_rate"])), ("Refusal rate", pct(s["refusal_rate"])),
            ("Canary exposures", f'{s["canary_exposure_count"]} of {s["total_cases"]} tests'),
            ("Instruction-following vulnerability rate", pct(s["instruction_following_vulnerability_rate"])),
            ("False refusal rate on benign controls", pct(s["false_refusal_rate"]))]
    st.markdown("<dl class='facts'>" + "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in rows) + "</dl>", unsafe_allow_html=True)


def results_frame(results: list[dict]) -> pd.DataFrame:
    return pd.DataFrame([{"ID": r["case_id"], "Category": CATEGORIES.get(r["category"], r["category"]), "Test": r["name"],
                          "Verdict": r["status"], "Severity": r["severity"], "Confidence": r.get("confidence", 0.0),
                          "Refused": r.get("refused", False), "Canary leaked": bool(r.get("canary_hits"))} for r in results])


def category_chart(results: list[dict]) -> go.Figure:
    attacks = [r for r in results if not r.get("is_control")]
    cats = [c for c in CATEGORIES if any(r["category"] == c for r in attacks)]
    fig = go.Figure()
    for s in STATUSES:
        fig.add_bar(y=[CATEGORIES[c] for c in cats], x=[sum(1 for r in attacks if r["category"] == c and r["status"] == s) for c in cats],
                    name=s, orientation="h", marker_color=STATUS_COLORS[s])
    fig.update_layout(barmode="stack", title="Verdicts by attack category", yaxis=dict(autorange="reversed"))
    return style_fig(fig, 80 + 34 * len(cats))


def result_detail(r: dict) -> None:
    c1, c2 = st.columns([1, 1])
    c1.markdown(f'<span class="pill s-{r["status"]}">{r["status"]}</span> &nbsp; severity <b>{html.escape(r["severity"])}</b> &nbsp; confidence <b>{r.get("confidence", 0):.0%}</b>', unsafe_allow_html=True)
    st.write(r.get("title", ""))
    st.caption(r.get("rationale", ""))
    c1.markdown("**Attack payload**")
    c1.code(r["prompt"], language=None)
    if r.get("document"):
        c1.markdown("**Attached document**")
        c1.code(r["document"], language=None)
    c2.markdown("**Target response** (untrusted, shown as plain text)")
    c2.code(r.get("response") or "(empty)", language=None)
    if r.get("evidence"):
        st.markdown("**Evidence**")
        for e in r["evidence"]:
            st.code(e, language=None)
    if r.get("recommendation"):
        st.markdown(f"**Recommendation.** {r['recommendation']}")
    if r.get("error"):
        st.error(r["error"])


def pick_assessment(db: Database, key: str, label: str = "Assessment") -> tuple[dict, list[dict]] | None:
    done = [a for a in db.list_assessments() if a["status"] == "complete"]
    if not done:
        return None
    ids = [a["id"] for a in done]
    fav = st.session_state.get("last_assessment_id")
    idx = ids.index(fav) if fav in ids else 0
    chosen = st.selectbox(label, ids, index=idx, key=key, format_func=lambda i: next(
        f'#{a["id"]}  {a["name"]}  ({when(a["created_at"])}, score {a["score"]["overall_score"]:.0f})' for a in done if a["id"] == i))
    a = next(x for x in done if x["id"] == chosen)
    return a, db.get_results(chosen)


# --------------------------------------------------------------------- pages
def page_overview(db: Database) -> None:
    st.title("Overview")
    done = [a for a in db.list_assessments() if a["status"] == "complete"]
    if not done:
        st.markdown('<div class="empty"><b>No assessments yet.</b><br>Run one against the built-in mock target to see how verdicts, scores and reports look. '
                    'It takes a few seconds and needs no API key.</div>', unsafe_allow_html=True)
        c1, c2, _ = st.columns([1, 1, 2])
        if c1.button("Run demo assessment"):
            out = AssessmentRunner(MockClient("basic"), DEFAULT_SYSTEM_PROMPT, db).run(get_cases(), "Demo, basic defence")
            st.session_state["last_assessment_id"] = out["assessment_id"]
            st.rerun()
        if c2.button("Configure an assessment"):
            goto("New assessment")
        return
    latest = done[0]
    results = db.get_results(latest["id"])
    show_reading(latest, results)
    left, right = st.columns([1, 1])
    with left:
        facts(latest["score"])
    with right:
        st.plotly_chart(category_chart(results))
    if len(done) > 1:
        ordered = list(reversed(done))
        fig = go.Figure(go.Scatter(x=[when(a["created_at"]) for a in ordered], y=[a["score"]["overall_score"] for a in ordered],
                                   mode="lines+markers", line=dict(color="#0E5A64", width=3), marker=dict(size=8),
                                   text=[a["name"] for a in ordered], hovertemplate="%{text}<br>score %{y}<extra></extra>"))
        fig.update_layout(title="Security score over time", yaxis=dict(range=[0, 100]))
        st.plotly_chart(style_fig(fig, 260))
    st.subheader("Recent assessments")
    st.dataframe(pd.DataFrame([{"ID": a["id"], "Name": a["name"], "Date": when(a["created_at"]), "Target": target_label(a["target"]),
                                "Score": a["score"]["overall_score"], "Grade": a["score"]["grade"],
                                "Confirmed": a["score"]["status_counts"]["confirmed"]} for a in done[:8]]), hide_index=True)


def build_cases(categories: list[str], controls: bool, uploads, add_marker: bool):
    cases = get_cases(categories, controls) if categories or controls else []
    notes = []
    for f in uploads or []:
        try:
            text = extract_text(f.name, f.getvalue())
            case, scan = case_from_document(f.name, text, add_marker)
            cases.append(case)
            notes.append((f.name, scan, None))
        except DocumentError as exc:
            notes.append((f.name, None, str(exc)))
    return cases, notes


def page_new(db: Database) -> None:
    st.title("New security assessment")
    st.caption("Attacks run against the local mock target by default. External endpoints need explicit authorization.")
    name = st.text_input("Assessment name", value=f"Assessment {datetime.now():%Y-%m-%d %H:%M}")
    kind = st.radio("Target", ["Built-in mock target", "External OpenAI-compatible endpoint"], horizontal=True)
    ext = external_defaults()
    client_factory = None
    if kind.startswith("Built-in"):
        defense = st.selectbox("Mock defence level", list(DEFENSES), index=1)
        st.caption(DEFENSES[defense])
        client_factory = lambda: MockClient(defense)  # noqa: E731
    else:
        st.markdown('<div class="notice"><b>Only test systems you own or have written permission to test.</b> '
                    'Probes are harmless markers and synthetic canaries, but they still generate traffic and cost on the target.</div>', unsafe_allow_html=True)
        c1, c2 = st.columns(2)
        base_url = c1.text_input("Base URL", value=ext["base_url"], help="Must be https, or http on localhost.")
        model = c2.text_input("Model", value=ext["model"])
        key = st.text_input("API key", type="password", placeholder="Using PIAL_API_KEY from .env" if ext["has_env_key"] else "Paste key (kept in memory only)")
        authorized = st.checkbox("I own this system or have written authorization to security-test it.")
        host_guess = ExternalTargetConfig(base_url, model).host
        confirm = st.text_input("Type the target hostname to confirm", placeholder=host_guess or "api.example.com")

        def client_factory():  # noqa: F811
            return OpenAICompatibleClient(ExternalTargetConfig(base_url, model, key or env_api_key(), authorized, confirm))

    with st.expander("Hidden system prompt sent to the target (synthetic canaries included)"):
        system_prompt = st.text_area("System prompt", value=DEFAULT_SYSTEM_PROMPT, height=260, label_visibility="collapsed")
        st.caption("Canaries: " + ", ".join(f"`{v}`" for v in CANARIES.values()) + ". Keep them in any custom prompt so leaks can be detected.")

    st.subheader("Tests")
    cats = st.multiselect("Attack categories", [c for c in CATEGORIES if c != "control"], default=[c for c in CATEGORIES if c != "control"],
                          format_func=lambda c: CATEGORIES[c])
    controls = st.checkbox("Include benign controls (measures over-refusal)", value=True)
    uploads = st.file_uploader(f"Upload test documents (TXT, PDF, DOCX, up to {MAX_UPLOAD_MB} MB each)", type=["txt", "pdf", "docx"], accept_multiple_files=True)
    add_marker = st.checkbox("Append a harmless test instruction to uploaded documents", value=False,
                             help="Lets the lab confirm compliance with an injected instruction in documents that have none.")
    cases, notes = build_cases(cats, controls, uploads, add_marker)
    for fname, scan, err in notes:
        if err:
            st.error(err)
        else:
            st.caption(f"{fname}: pre-scan {scan.level} risk (score {scan.score})" + (f", signals: {', '.join(scan.names)}" if scan.signals else ""))
    st.write(f"**{len(cases)}** tests selected.")

    if st.button("Run assessment", disabled=not cases):
        try:
            client = client_factory()
        except UnauthorizedTargetError as exc:
            st.error(str(exc))
            return
        bar = st.progress(0.0, text="Starting")
        runner = AssessmentRunner(client, system_prompt, db, REQUEST_DELAY_S,
                                  lambda i, n, r: bar.progress(i / n, text=f"{i}/{n}  {r['case_id']}  {r['status']}"))
        try:
            out = runner.run(cases, name)
        except Exception as exc:  # noqa: BLE001
            st.error(f"Assessment failed: {exc}")
            return
        bar.empty()
        st.session_state["last_assessment_id"] = out["assessment_id"]
        st.session_state["last_run"] = out["assessment_id"]
    run_id = st.session_state.get("last_run")
    if run_id and db.get_assessment(run_id):
        a, rs = db.get_assessment(run_id), db.get_results(run_id)
        st.divider()
        st.subheader("Result")
        show_reading(a, rs)
        facts(a["score"])
        st.dataframe(results_frame(rs), hide_index=True)
        if st.button("Open security report"):
            goto("Security reports")


def page_library() -> None:
    st.title("Attack library")
    cases = get_cases()
    c1, c2 = st.columns([2, 1])
    cats = c1.multiselect("Category", list(CATEGORIES), format_func=lambda c: CATEGORIES[c])
    q = c2.text_input("Search")
    shown = [c for c in cases if (not cats or c.category in cats) and (not q or q.lower() in f"{c.id} {c.name} {c.description}".lower())]
    st.caption(f"{len(shown)} of {len(cases)} cases. Probes use harmless INJ_ markers and synthetic canaries.")
    for c in shown:
        with st.expander(f"{c.id}   {c.name}   ({c.severity})"):
            st.write(c.description)
            st.caption(f"{c.category_label}. Techniques: {', '.join(c.techniques)}. Success criterion: "
                       + (f"target emits `{c.success_marker}`" if c.success_marker else "a canary or prompt text is exposed" if c.targets_canary else "should be answered normally"))
            st.code(c.prompt, language=None)
            if c.document:
                st.code(c.document, language=None)
            scan = scan_text(f"{c.document or ''}\n{c.prompt}")
            st.caption(f"Input scanner: {scan.level} (score {scan.score}) {', '.join(scan.names)}")
            st.markdown(f"**Mitigation.** {c.recommendation}")


def page_history(db: Database) -> None:
    st.title("Test history")
    items = db.list_assessments()
    if not items:
        st.markdown('<div class="empty">No saved assessments. Run one from <b>New assessment</b>.</div>', unsafe_allow_html=True)
        return
    st.dataframe(pd.DataFrame([{"ID": a["id"], "Name": a["name"], "Date": when(a["created_at"]), "Target": target_label(a["target"]),
                                "Status": a["status"], "Tests": a["total_cases"],
                                "Score": (a["score"] or {}).get("overall_score"), "Grade": (a["score"] or {}).get("grade")} for a in items]), hide_index=True)
    ids = [a["id"] for a in items]
    sel = st.selectbox("Open assessment", ids, format_func=lambda i: f"#{i}  {next(a['name'] for a in items if a['id'] == i)}")
    a, rs = db.get_assessment(sel), db.get_results(sel)
    if a["score"]:
        show_reading(a, rs)
    flt = st.multiselect("Verdict filter", STATUSES, default=STATUSES)
    view = [r for r in rs if r["status"] in flt]
    st.dataframe(results_frame(view), hide_index=True)
    if view:
        pick = st.selectbox("Inspect test", [r["case_id"] for r in view], format_func=lambda cid: next(f"{r['case_id']}  {r['name']}" for r in view if r["case_id"] == cid))
        result_detail(next(r for r in view if r["case_id"] == pick))
    st.divider()
    if st.checkbox(f"Delete assessment #{sel} permanently") and st.button("Delete assessment"):
        db.delete_assessment(sel)
        st.session_state.pop("last_run", None)
        st.rerun()


def page_analytics(db: Database) -> None:
    st.title("Vulnerability analytics")
    rows = db.all_results()
    if not rows:
        st.markdown('<div class="empty">Analytics appear after your first assessment.</div>', unsafe_allow_html=True)
        return
    targets = sorted({r["defense"] for r in rows})
    chosen = st.multiselect("Targets", targets, default=targets)
    rows = [r for r in rows if r["defense"] in chosen]
    atk = [r for r in rows if not r["is_control"]]
    if not atk:
        st.info("Nothing to show for this selection.")
        return
    c1, c2 = st.columns(2)
    with c1:
        st.plotly_chart(category_chart(atk))
    with c2:
        tech: dict[str, list[int]] = {}
        for r in atk:
            for t in r["techniques"]:
                tech.setdefault(t, [0, 0])
                tech[t][1] += 1
                tech[t][0] += r["status"] == "confirmed"
        names = sorted(tech, key=lambda t: tech[t][0] / tech[t][1])
        fig = go.Figure(go.Bar(y=names, x=[tech[t][0] / tech[t][1] for t in names], orientation="h", marker_color="#0E5A64",
                               text=[f"{tech[t][0]}/{tech[t][1]}" for t in names], textposition="outside"))
        fig.update_layout(title="Attack success rate by technique", xaxis=dict(range=[0, 1.15], tickformat=".0%"))
        st.plotly_chart(style_fig(fig, 80 + 28 * len(names)))
    c3, c4 = st.columns(2)
    with c3:
        sev_order = ["critical", "high", "medium", "low", "info"]
        fig = go.Figure()
        for s in ("confirmed", "suspected", "inconclusive"):
            fig.add_bar(x=sev_order, y=[sum(1 for r in atk if r["status"] == s and r["severity"] == v) for v in sev_order], name=s, marker_color=STATUS_COLORS[s])
        fig.update_layout(barmode="stack", title="Findings by severity")
        st.plotly_chart(style_fig(fig))
    with c4:
        counts: dict[str, int] = {}
        for r in rows:
            for h in r["canary_hits"]:
                counts[h["name"]] = counts.get(h["name"], 0) + 1
        fig = go.Figure(go.Bar(x=list(CANARIES), y=[counts.get(k, 0) for k in CANARIES], marker_color="#B3261E"))
        fig.update_layout(title="Canary exposures by secret")
        st.plotly_chart(style_fig(fig))
    st.subheader("Most effective attacks")
    agg: dict[str, dict] = {}
    for r in atk:
        d = agg.setdefault(r["case_id"], {"ID": r["case_id"], "Attack": r["name"], "Runs": 0, "Confirmed": 0, "Suspected": 0})
        d["Runs"] += 1
        d["Confirmed"] += r["status"] == "confirmed"
        d["Suspected"] += r["status"] == "suspected"
    st.dataframe(pd.DataFrame(sorted(agg.values(), key=lambda d: (-d["Confirmed"] / d["Runs"], -d["Suspected"]))[:15]), hide_index=True)


def page_reports(db: Database) -> None:
    st.title("Security reports")
    picked = pick_assessment(db, "report_pick")
    if not picked:
        st.markdown('<div class="empty">No completed assessments to report on yet.</div>', unsafe_allow_html=True)
        return
    a, rs = picked
    report = build_report(a, rs)
    stamp = f"pial-{a['id']}-{(a['created_at'] or '')[:10]}"
    show_reading(a, rs)
    c1, c2, c3 = st.columns(3)
    c1.download_button("Download JSON", report_to_json(report), f"{stamp}.json", "application/json")
    c2.download_button("Download CSV", results_to_csv(rs), f"{stamp}.csv", "text/csv")
    try:
        c3.download_button("Download PDF", report_to_pdf(report), f"{stamp}.pdf", "application/pdf")
    except Exception as exc:  # noqa: BLE001
        c3.error(f"PDF failed: {exc}")
    st.subheader(f"Findings ({len(report['findings'])})")
    for f in report["findings"]:
        with st.expander(f"{f['status']}  |  {f['case_id']}  {f['title']}  ({f['severity']})"):
            st.write(f["rationale"])
            for e in f["evidence"] or []:
                st.code(e, language=None)
            st.markdown(f"**Recommendation.** {f['recommendation'] or 'Manual review.'}")
    if not report["findings"]:
        st.success("No confirmed, suspected or inconclusive findings for the cases tested.")
    st.caption(report["disclaimer"])


def page_settings(db: Database) -> None:
    st.title("Settings")
    ext = external_defaults()
    st.markdown("<dl class='facts'>"
                f"<dt>Version</dt><dd>{VERSION}</dd><dt>Database</dt><dd>{html.escape(str(DB_PATH))}</dd>"
                f"<dt>Assessments stored</dt><dd>{len(db.list_assessments())}</dd>"
                f"<dt>API key in environment</dt><dd>{'yes' if ext['has_env_key'] else 'no'}</dd>"
                f"<dt>Default external endpoint</dt><dd>{html.escape(ext['base_url'])}</dd>"
                f"<dt>Request delay for external targets</dt><dd>{REQUEST_DELAY_S}s</dd></dl>", unsafe_allow_html=True)
    st.caption("Change defaults in `.env` (see `.env.example`). API keys are never stored in the database, reports or logs.")
    st.subheader("Authorization policy")
    st.write("The lab only attacks the local mock target unless you tick the authorization box and type the exact hostname of an external endpoint. "
             "Remote targets must use https. Cloud metadata addresses are blocked.")
    st.subheader("Synthetic canaries")
    st.table(pd.DataFrame({"Name": list(CANARIES), "Value": list(CANARIES.values())}))
    st.subheader("Sample documents")
    st.caption("Adversarial TXT, DOCX and PDF files for indirect-injection tests.")
    if st.button("Regenerate sample documents"):
        write_sample_documents(SAMPLE_DOCS_DIR)
    files = sorted(SAMPLE_DOCS_DIR.glob("*")) if SAMPLE_DOCS_DIR.exists() else []
    if files:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            for p in files:
                z.write(p, p.name)
        st.download_button("Download sample documents (zip)", buf.getvalue(), "pial-sample-documents.zip", "application/zip")
    st.subheader("Danger zone")
    if st.checkbox("I understand this deletes every assessment and result") and st.button("Delete all data"):
        db.delete_all()
        st.session_state.pop("last_run", None)
        st.session_state.pop("last_assessment_id", None)
        st.rerun()


# ---------------------------------------------------------------------- main
def main() -> None:
    load_css()
    db = get_db()
    if "nav_request" in st.session_state:
        st.session_state["page"] = st.session_state.pop("nav_request")
    with st.sidebar:
        st.markdown('<div class="brand">Prompt Injection<br>Attack Lab</div><div class="brand-sub">Local, authorized testing of LLM applications</div>', unsafe_allow_html=True)
        page = st.radio("Navigate", PAGES, key="page", label_visibility="collapsed")
        st.caption(f"v{VERSION}")
    {"Overview": lambda: page_overview(db), "New assessment": lambda: page_new(db), "Attack library": page_library,
     "Test history": lambda: page_history(db), "Vulnerability analytics": lambda: page_analytics(db),
     "Security reports": lambda: page_reports(db), "Settings": lambda: page_settings(db)}[page]()


main()
