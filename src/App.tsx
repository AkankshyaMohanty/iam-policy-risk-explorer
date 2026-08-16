import { useEffect, useMemo, useState } from "react";
import { analyzePolicy, type Finding, type RiskLabel } from "./analyzer";

const examples = [
  {
    id: "admin",
    name: "Administrator-like",
    description: "Wildcard action and resource — intentionally dangerous.",
    policy: {
      Version: "2012-10-17",
      Statement: [{ Sid: "AdminAccess", Effect: "Allow", Action: "*", Resource: "*" }],
    },
  },
  {
    id: "s3",
    name: "Scoped S3 access",
    description: "Read/write access limited to one application bucket.",
    policy: {
      Version: "2012-10-17",
      Statement: [
        { Sid: "BucketMetadata", Effect: "Allow", Action: ["s3:ListBucket", "s3:GetBucketLocation"], Resource: "arn:aws:s3:::example-app-data" },
        { Sid: "ObjectAccess", Effect: "Allow", Action: ["s3:GetObject", "s3:PutObject"], Resource: "arn:aws:s3:::example-app-data/*" },
      ],
    },
  },
  {
    id: "iam",
    name: "Risky IAM operations",
    description: "Broad role-management permissions including PassRole.",
    policy: {
      Version: "2012-10-17",
      Statement: [{
        Sid: "ManageRoles",
        Effect: "Allow",
        Action: ["iam:CreateRole", "iam:AttachRolePolicy", "iam:PassRole", "iam:PutRolePolicy"],
        Resource: "*",
      }],
    },
  },
  {
    id: "logs",
    name: "CloudWatch read only",
    description: "Read-oriented CloudWatch Logs permissions.",
    policy: {
      Version: "2012-10-17",
      Statement: [{
        Sid: "ReadLogs",
        Effect: "Allow",
        Action: ["logs:DescribeLogGroups", "logs:DescribeLogStreams", "logs:GetLogEvents", "logs:FilterLogEvents"],
        Resource: "*",
      }],
    },
  },
];

const starter = JSON.stringify(examples[0].policy, null, 2);
const primary = "inline-flex items-center justify-center gap-2 rounded-xl bg-blue-600 px-4 py-2.5 text-sm font-bold text-white shadow-sm transition hover:bg-blue-700 focus:outline-none focus:ring-4 focus:ring-blue-100";
const secondary = "inline-flex items-center justify-center gap-2 rounded-xl border border-slate-200 bg-white px-3.5 py-2.5 text-sm font-semibold text-slate-700 transition hover:border-slate-300 hover:bg-slate-50";

function useStoredPolicy() {
  const [value, setValue] = useState(() => {
    try { return localStorage.getItem("policyscope.policy") || starter; }
    catch { return starter; }
  });
  useEffect(() => {
    try { localStorage.setItem("policyscope.policy", value); } catch {}
  }, [value]);
  return [value, setValue] as const;
}

function icon(name: string) {
  const path: Record<string, React.ReactNode> = {
    shield: <><path d="M12 3 5 6v5c0 5 3 8.5 7 10 4-1.5 7-5 7-10V6z"/><path d="m9 12 2 2 4-4"/></>,
    search: <><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></>,
    alert: <><path d="M10.3 3.7 2.6 17a2 2 0 0 0 1.7 3h15.4a2 2 0 0 0 1.7-3L13.7 3.7a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></>,
    check: <path d="m5 12 4 4L19 6"/>,
    code: <><path d="m8 9-3 3 3 3"/><path d="m16 9 3 3-3 3"/><path d="m14 5-4 14"/></>,
    copy: <><rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/></>,
    trash: <><path d="M4 7h16"/><path d="M9 7V4h6v3"/><path d="m6 7 1 14h10l1-14"/></>,
    download: <><path d="M12 3v12"/><path d="m7 10 5 5 5-5"/><path d="M5 21h14"/></>,
    layers: <><path d="m12 3 9 5-9 5-9-5z"/><path d="m3 12 9 5 9-5"/><path d="m3 16 9 5 9-5"/></>,
  };
  return <svg aria-hidden="true" fill="none" height="18" viewBox="0 0 24 24" width="18" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8">{path[name]}</svg>;
}

export default function App() {
  const [policyText, setPolicyText] = useStoredPolicy();
  const [analysisText, setAnalysisText] = useState(policyText);
  const [selectedExample, setSelectedExample] = useState("admin");
  const [copied, setCopied] = useState(false);
  const result = useMemo(() => analyzePolicy(analysisText), [analysisText]);

  function loadExample(id: string) {
    const ex = examples.find(item => item.id === id) || examples[0];
    const text = JSON.stringify(ex.policy, null, 2);
    setSelectedExample(id);
    setPolicyText(text);
    setAnalysisText(text);
  }

  function analyze() {
    try {
      const formatted = JSON.stringify(JSON.parse(policyText), null, 2);
      setPolicyText(formatted);
      setAnalysisText(formatted);
    } catch {
      setAnalysisText(policyText);
    }
  }

  async function copyPolicy() {
    try {
      await navigator.clipboard.writeText(policyText);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
    } catch {}
  }

  function exportAnalysis() {
    const blob = new Blob([JSON.stringify({
      generatedAt: new Date().toISOString(),
      policy: (() => { try { return JSON.parse(analysisText); } catch { return analysisText; } })(),
      analysis: result,
      disclaimer: "Static educational analysis only. Not AWS IAM Access Analyzer or an authorization decision.",
    }, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "iam-policy-analysis.json";
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="min-h-screen bg-[#f5f7fb]">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-[1500px] items-center justify-between gap-4 px-4 py-4 sm:px-6 lg:px-8">
          <div className="flex items-center gap-3">
            <span className="grid size-11 place-items-center rounded-2xl bg-slate-950 text-white shadow-lg shadow-slate-950/15">{icon("shield")}</span>
            <div><p className="text-lg font-bold tracking-tight text-slate-950">PolicyScope</p><p className="text-xs text-slate-500">IAM Policy Risk Explorer</p></div>
          </div>
          <div className="hidden items-center gap-2 rounded-full border border-emerald-100 bg-emerald-50 px-3 py-1.5 text-xs font-bold text-emerald-700 sm:flex"><span className="size-2 rounded-full bg-emerald-500"/>No AWS credentials required</div>
        </div>
      </header>

      <main className="mx-auto max-w-[1500px] px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
        <section className="mb-7">
          <p className="text-xs font-bold uppercase tracking-[0.18em] text-blue-600">Cloud security lab</p>
          <h1 className="mt-2 max-w-5xl text-3xl font-bold tracking-tight text-slate-950 sm:text-4xl">Understand the blast radius of an IAM policy before you trust it.</h1>
          <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-500 sm:text-base">Paste an AWS IAM policy to inspect broad permissions, wildcard resources, sensitive IAM operations, conditions, service access, and statement-level risk.</p>
        </section>

        <div className="grid items-start gap-6 xl:grid-cols-[minmax(360px,0.85fr)_minmax(0,1.45fr)]">
          <section className="overflow-hidden rounded-3xl border border-slate-200 bg-white shadow-sm xl:sticky xl:top-6">
            <div className="border-b border-slate-100 px-5 py-4"><div className="flex items-center gap-2 text-blue-600">{icon("code")}<h2 className="font-bold text-slate-950">Policy editor</h2></div><p className="mt-1 text-xs text-slate-500">Policy text is stored only in your browser.</p></div>
            <div className="border-b border-slate-100 p-5">
              <label className="text-xs font-bold uppercase tracking-[0.14em] text-slate-400">Load example</label>
              <select className="mt-2 w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none focus:border-blue-400 focus:ring-4 focus:ring-blue-50" value={selectedExample} onChange={e => loadExample(e.target.value)}>
                {examples.map(ex => <option key={ex.id} value={ex.id}>{ex.name}</option>)}
              </select>
              <p className="mt-2 text-xs leading-5 text-slate-400">{examples.find(ex => ex.id === selectedExample)?.description}</p>
            </div>
            <div className="p-5">
              <textarea aria-label="IAM policy JSON" spellCheck={false} value={policyText} onChange={e => setPolicyText(e.target.value)} className="min-h-[520px] w-full resize-y rounded-2xl border border-slate-800 bg-slate-950 p-4 font-mono text-[12px] leading-6 text-slate-200 outline-none focus:border-blue-500 focus:ring-4 focus:ring-blue-100"/>
              <div className="mt-3 flex flex-wrap gap-2">
                <button className={primary} onClick={analyze}>{icon("search")}Analyze policy</button>
                <button className={secondary} onClick={copyPolicy}>{icon("copy")}{copied ? "Copied" : "Copy"}</button>
                <button className={secondary} onClick={() => setPolicyText("")}>{icon("trash")}Clear</button>
              </div>
            </div>
          </section>

          <div className="min-w-0 space-y-6">
            {result.parseError ? (
              <section className="rounded-3xl border border-red-200 bg-red-50 p-6 shadow-sm">
                <div className="flex gap-3"><span className="grid size-10 shrink-0 place-items-center rounded-2xl bg-red-100 text-red-700">{icon("alert")}</span><div><h2 className="font-bold text-red-950">Invalid JSON</h2><p className="mt-2 text-sm leading-6 text-red-700">{result.parseError}</p><p className="mt-2 text-xs text-red-600">Fix the JSON and click Analyze policy again.</p></div></div>
              </section>
            ) : (
              <>
                <section className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm sm:p-6">
                  <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
                    <RiskScore score={result.score} label={result.riskLabel}/>
                    <div className="grid flex-1 grid-cols-2 gap-3 sm:grid-cols-4 lg:max-w-2xl">
                      <Stat label="Statements" value={result.summary.statements}/><Stat label="Services" value={result.summary.services}/><Stat label="Actions" value={result.summary.actions}/><Stat label="Findings" value={result.findings.length}/>
                    </div>
                  </div>
                  {!!result.structuralErrors.length && <div className="mt-5 rounded-2xl border border-amber-100 bg-amber-50 p-4"><p className="text-xs font-bold uppercase tracking-[0.14em] text-amber-700">Structure warnings</p><ul className="mt-2 space-y-1.5 text-sm text-amber-800">{result.structuralErrors.map(error => <li key={error}>• {error}</li>)}</ul></div>}
                </section>

                <section className="grid gap-6 2xl:grid-cols-[1.1fr_0.9fr]">
                  <div className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm sm:p-6">
                    <div className="flex items-start justify-between gap-4"><div><h2 className="font-bold text-slate-950">Security findings</h2><p className="mt-1 text-xs text-slate-500">Heuristic checks for broad or sensitive permission patterns.</p></div><span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-bold text-slate-600">{result.summary.critical} critical · {result.summary.high} high</span></div>
                    <div className="mt-5 space-y-3">{result.findings.map(f => <FindingCard key={f.id} finding={f}/>)}</div>
                  </div>

                  <div className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm sm:p-6">
                    <div className="flex items-center gap-2 text-blue-600">{icon("layers")}<h2 className="font-bold text-slate-950">Permission map</h2></div><p className="mt-1 text-xs text-slate-500">Actions grouped by AWS service prefix.</p>
                    <div className="mt-5 space-y-3">{result.services.length ? result.services.map(service => <details key={service.service} open={result.services.length <= 4} className="rounded-2xl border border-slate-200"><summary className="cursor-pointer list-none px-4 py-3.5"><div className="flex items-center justify-between gap-3"><div><p className="text-sm font-bold text-slate-900">{service.service === "All services" ? service.service : service.service.toUpperCase()}</p><p className="mt-0.5 text-xs text-slate-500">{service.actions.length} action{service.actions.length === 1 ? "" : "s"}</p></div><span className="rounded-full bg-blue-50 px-2 py-1 text-xs font-bold text-blue-700">{service.actions.length}</span></div></summary><div className="border-t border-slate-100 px-4 py-3"><div className="flex flex-wrap gap-2">{service.actions.map(action => <code key={action} className="rounded-lg bg-slate-100 px-2.5 py-1.5 text-[11px] font-semibold text-slate-600">{action}</code>)}</div></div></details>) : <p className="text-sm text-slate-500">No actions to visualize.</p>}</div>
                  </div>
                </section>

                <section className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm sm:p-6">
                  <h2 className="font-bold text-slate-950">Statement breakdown</h2><p className="mt-1 text-xs text-slate-500">Human-friendly view of each policy statement.</p>
                  <div className="mt-5 grid gap-4 lg:grid-cols-2">{result.statements.map(s => <StatementCard key={`${s.index}-${s.sid || "statement"}`} statement={s}/>)}</div>
                </section>

                <section className="rounded-3xl bg-slate-950 p-5 text-white shadow-xl shadow-slate-950/10 sm:p-6">
                  <div className="flex flex-col gap-5 sm:flex-row sm:items-center sm:justify-between"><div><h2 className="font-bold">Export this analysis</h2><p className="mt-1 max-w-2xl text-sm leading-6 text-slate-400">Download the input policy, findings, risk score, and statement analysis as JSON for demos or project documentation.</p></div><button className="inline-flex shrink-0 items-center justify-center gap-2 rounded-xl bg-white px-4 py-2.5 text-sm font-bold text-slate-950 transition hover:bg-slate-100" onClick={exportAnalysis}>{icon("download")}Export JSON</button></div>
                </section>
              </>
            )}

            <section className="rounded-3xl border border-blue-100 bg-blue-50 p-5">
              <div className="flex gap-3"><span className="grid size-10 shrink-0 place-items-center rounded-2xl bg-blue-100 text-blue-700">{icon("shield")}</span><div><h2 className="font-bold text-blue-950">Educational static analyzer</h2><p className="mt-1 text-sm leading-6 text-blue-800">PolicyScope does not call AWS or evaluate the full IAM authorization context. SCPs, resource policies, permissions boundaries, session policies, service-specific semantics, and request context can change effective permissions.</p></div></div>
            </section>
          </div>
        </div>
      </main>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return <div className="rounded-2xl bg-slate-50 px-4 py-3"><p className="text-[10px] font-bold uppercase tracking-[0.14em] text-slate-400">{label}</p><p className="mt-1.5 text-xl font-bold text-slate-950">{value}</p></div>;
}

function RiskScore({ score, label }: { score: number; label: RiskLabel }) {
  const circle: Record<RiskLabel, string> = { Low: "border-emerald-400 text-emerald-700", Medium: "border-amber-400 text-amber-700", High: "border-orange-400 text-orange-700", Critical: "border-red-400 text-red-700" };
  const badge: Record<RiskLabel, string> = { Low: "bg-emerald-50 text-emerald-700", Medium: "bg-amber-50 text-amber-700", High: "bg-orange-50 text-orange-700", Critical: "bg-red-50 text-red-700" };
  return <div className="flex items-center gap-4"><div className={`grid size-20 shrink-0 place-items-center rounded-full border-[7px] bg-white text-2xl font-bold ${circle[label]}`}>{score}</div><div><p className="text-xs font-bold uppercase tracking-[0.16em] text-slate-400">Policy risk</p><span className={`mt-2 inline-flex rounded-full px-3 py-1 text-xs font-bold ${badge[label]}`}>{label}</span><p className="mt-2 text-xs leading-5 text-slate-500">Static heuristic score from 0–100.</p></div></div>;
}

function FindingCard({ finding }: { finding: Finding }) {
  const style: Record<Finding["severity"], string> = { critical: "border-red-100 bg-red-50/70", high: "border-orange-100 bg-orange-50/70", medium: "border-amber-100 bg-amber-50/70", low: "border-emerald-100 bg-emerald-50/70", info: "border-blue-100 bg-blue-50/70" };
  const badge: Record<Finding["severity"], string> = { critical: "bg-red-100 text-red-700", high: "bg-orange-100 text-orange-700", medium: "bg-amber-100 text-amber-700", low: "bg-emerald-100 text-emerald-700", info: "bg-blue-100 text-blue-700" };
  return <article className={`rounded-2xl border p-4 ${style[finding.severity]}`}><div className="flex gap-3"><span className={`mt-0.5 grid size-9 shrink-0 place-items-center rounded-xl ${badge[finding.severity]}`}>{icon(finding.severity === "low" || finding.severity === "info" ? "check" : "alert")}</span><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><h3 className="text-sm font-bold text-slate-950">{finding.title}</h3><span className={`rounded-full px-2 py-0.5 text-[10px] font-bold uppercase ${badge[finding.severity]}`}>{finding.severity}</span>{typeof finding.statementIndex === "number" && <span className="text-[11px] font-semibold text-slate-400">Statement {finding.statementIndex + 1}</span>}</div><p className="mt-2 text-sm leading-6 text-slate-600">{finding.message}</p>{finding.evidence && <code className="mt-3 block overflow-x-auto rounded-xl border border-black/5 bg-white/70 px-3 py-2 text-xs text-slate-700">{finding.evidence}</code>}{finding.recommendation && <div className="mt-3 rounded-xl bg-white/70 px-3 py-2.5"><p className="text-[10px] font-bold uppercase tracking-[0.14em] text-slate-400">Improvement</p><p className="mt-1 text-xs leading-5 text-slate-600">{finding.recommendation}</p></div>}</div></div></article>;
}

function StatementCard({ statement }: { statement: ReturnType<typeof analyzePolicy>["statements"][number] }) {
  const risk: Record<RiskLabel, string> = { Low: "bg-emerald-50 text-emerald-700", Medium: "bg-amber-50 text-amber-700", High: "bg-orange-50 text-orange-700", Critical: "bg-red-50 text-red-700" };
  const allow = statement.effect.toLowerCase() === "allow";
  return <article className="rounded-2xl border border-slate-200 bg-white p-4"><div className="flex flex-wrap items-start justify-between gap-3"><div><p className="text-[10px] font-bold uppercase tracking-[0.16em] text-slate-400">Statement {statement.index + 1}</p><h3 className="mt-1 font-bold text-slate-950">{statement.sid || "Unnamed statement"}</h3></div><div className="flex gap-2"><span className={`rounded-full px-2.5 py-1 text-xs font-bold ${allow ? "bg-blue-50 text-blue-700" : "bg-slate-900 text-white"}`}>{statement.effect}</span><span className={`rounded-full px-2.5 py-1 text-xs font-bold ${risk[statement.riskLabel]}`}>{statement.riskLabel}</span></div></div><div className="mt-4 grid gap-3 sm:grid-cols-3"><Mini label="Services" value={statement.services.join(", ") || "—"}/><Mini label="Actions" value={String(statement.actions.length)}/><Mini label="Conditions" value={statement.hasCondition ? "Present" : "None"}/></div><div className="mt-4"><p className="text-[10px] font-bold uppercase tracking-[0.14em] text-slate-400">Resources</p><div className="mt-2 space-y-1.5">{statement.resources.length ? statement.resources.slice(0, 4).map(resource => <code key={resource} className="block overflow-x-auto rounded-lg bg-slate-50 px-2.5 py-2 text-[11px] text-slate-600">{resource}</code>) : <p className="text-xs text-slate-500">No resource value detected.</p>}</div></div></article>;
}

function Mini({ label, value }: { label: string; value: string }) {
  return <div className="rounded-xl bg-slate-50 px-3 py-2.5"><p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">{label}</p><p className="mt-1 truncate text-xs font-semibold text-slate-700" title={value}>{value}</p></div>;
}
