export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type RiskLabel = "Low" | "Medium" | "High" | "Critical";

type StringOrStrings = string | string[];
type Statement = {
  Sid?: string;
  Effect?: string;
  Action?: StringOrStrings;
  NotAction?: StringOrStrings;
  Resource?: StringOrStrings;
  NotResource?: StringOrStrings;
  Principal?: unknown;
  Condition?: Record<string, unknown>;
};
type Policy = { Version?: string; Statement?: Statement | Statement[] };

export type Finding = {
  id: string;
  severity: Severity;
  title: string;
  message: string;
  recommendation?: string;
  evidence?: string;
  statementIndex?: number;
  score: number;
};

export type StatementAnalysis = {
  index: number;
  sid?: string;
  effect: string;
  actions: string[];
  resources: string[];
  services: string[];
  hasCondition: boolean;
  score: number;
  riskLabel: RiskLabel;
};

export type Analysis = {
  parseError?: string;
  structuralErrors: string[];
  score: number;
  riskLabel: RiskLabel;
  findings: Finding[];
  statements: StatementAnalysis[];
  services: { service: string; actions: string[] }[];
  summary: {
    statements: number;
    services: number;
    actions: number;
    resources: number;
    critical: number;
    high: number;
  };
};

const escalation = new Set([
  "iam:passrole",
  "iam:createpolicyversion",
  "iam:setdefaultpolicyversion",
  "iam:attachuserpolicy",
  "iam:attachrolepolicy",
  "iam:putuserpolicy",
  "iam:putrolepolicy",
  "iam:createaccesskey",
  "lambda:updatefunctioncode",
  "lambda:createfunction",
]);
const destructiveVerbs = ["delete", "terminate", "remove", "detach", "destroy", "disable", "stop", "revoke", "purge"];
const severityOrder: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const arr = (value?: StringOrStrings) => Array.isArray(value) ? value : typeof value === "string" ? [value] : [];
const uniq = <T,>(items: T[]) => [...new Set(items)];
const statementsOf = (policy: Policy) => Array.isArray(policy.Statement) ? policy.Statement : policy.Statement ? [policy.Statement] : [];
const serviceOf = (action: string) => action === "*" ? "All services" : action.split(":")[0] || "Unknown";
const labelFor = (score: number): RiskLabel => score >= 75 ? "Critical" : score >= 50 ? "High" : score >= 25 ? "Medium" : "Low";

function principalHasWildcard(value: unknown): boolean {
  if (value === "*") return true;
  if (Array.isArray(value)) return value.some(principalHasWildcard);
  if (value && typeof value === "object") return Object.values(value as Record<string, unknown>).some(principalHasWildcard);
  return false;
}

function add(
  findings: Finding[], id: string, severity: Severity, title: string, message: string,
  score: number, statementIndex?: number, evidence?: string, recommendation?: string,
) {
  findings.push({ id, severity, title, message, score, statementIndex, evidence, recommendation });
}

function empty(parseError: string): Analysis {
  return {
    parseError,
    structuralErrors: [], score: 0, riskLabel: "Low", findings: [], statements: [], services: [],
    summary: { statements: 0, services: 0, actions: 0, resources: 0, critical: 0, high: 0 },
  };
}

export function analyzePolicy(raw: string): Analysis {
  let policy: Policy;
  try {
    policy = JSON.parse(raw) as Policy;
  } catch (error) {
    return empty(error instanceof Error ? error.message : "Invalid JSON.");
  }
  if (!policy || typeof policy !== "object" || Array.isArray(policy)) return empty("The policy must be a JSON object.");

  const statements = statementsOf(policy);
  const structuralErrors: string[] = [];
  if (!policy.Version) structuralErrors.push("Missing top-level Version.");
  if (!statements.length) structuralErrors.push("Statement must contain at least one policy statement.");
  statements.forEach((s, i) => {
    if (!s.Effect) structuralErrors.push(`Statement ${i + 1}: missing Effect.`);
    if (!s.Action && !s.NotAction) structuralErrors.push(`Statement ${i + 1}: missing Action or NotAction.`);
    if (!s.Resource && !s.NotResource && !s.Principal) structuralErrors.push(`Statement ${i + 1}: missing Resource/NotResource for an identity policy.`);
  });

  const findings: Finding[] = [];
  const statementAnalyses: StatementAnalysis[] = [];

  statements.forEach((s, i) => {
    const actions = arr(s.Action);
    const notActions = arr(s.NotAction);
    const resources = arr(s.Resource);
    const notResources = arr(s.NotResource);
    const isAllow = (s.Effect || "").toLowerCase() === "allow";
    const hasCondition = !!s.Condition && Object.keys(s.Condition).length > 0;
    let score = 0;

    if (isAllow && actions.includes("*")) {
      add(findings, `wildcard-action-${i}`, "critical", "Wildcard action grants all actions",
        'This Allow statement contains Action "*", potentially granting permissions across every AWS service.', 35, i,
        'Action: "*"', "Replace the wildcard with the smallest explicit action set the workload requires.");
      score += 35;
    }

    const serviceWildcards = actions.filter(a => a !== "*" && a.endsWith(":*"));
    if (isAllow && serviceWildcards.length) {
      add(findings, `service-wildcard-${i}`, "high", "Broad service-level permissions",
        "One or more AWS services allow every API operation in that service.", 22, i, serviceWildcards.join(", "),
        "Enumerate only the service actions actually required.");
      score += 22;
    }

    if (isAllow && resources.includes("*")) {
      add(findings, `wildcard-resource-${i}`, actions.includes("*") ? "critical" : "high", "Wildcard resource scope",
        "The statement is not scoped to specific resource ARNs.", 20, i, 'Resource: "*"',
        "Where supported, scope Resource to the specific ARNs the application needs.");
      score += 20;
    }

    if (isAllow && principalHasWildcard(s.Principal)) {
      add(findings, `wildcard-principal-${i}`, "critical", "Wildcard principal",
        "A wildcard Principal can create broad trust or public access depending on the policy type and conditions.", 30, i,
        'Principal contains "*"', "Restrict Principal to trusted accounts, roles, services, or federated identities.");
      score += 30;
    }

    if (isAllow && notActions.length) {
      add(findings, `not-action-${i}`, "high", "Allow with NotAction",
        "Allow + NotAction can grant a much broader permission set than its exclusions suggest.", 20, i,
        `NotAction: ${notActions.join(", ")}`, "Prefer explicit Action entries when practical.");
      score += 20;
    }

    if (isAllow && notResources.length) {
      add(findings, `not-resource-${i}`, "high", "Allow with NotResource",
        "Allow + NotResource can apply to almost every resource except the exclusions.", 20, i,
        `NotResource: ${notResources.join(", ")}`, "Prefer explicit Resource scoping for allow statements.");
      score += 20;
    }

    const escalationActions = actions.filter(a => escalation.has(a.toLowerCase()));
    if (isAllow && escalationActions.length) {
      add(findings, `escalation-${i}`, "high", "Privilege-escalation-sensitive actions",
        "This statement contains delegation, policy-change, credential, or executable-code actions that deserve extra review.", 18, i,
        escalationActions.join(", "), "Scope these permissions tightly and apply resource/condition restrictions where possible.");
      score += 18;
    }

    const destructive = actions.filter(a => {
      const operation = a.split(":")[1]?.toLowerCase() || "";
      return destructiveVerbs.some(v => operation.startsWith(v));
    });
    if (isAllow && destructive.length && resources.includes("*")) {
      add(findings, `destructive-${i}`, "high", "Destructive actions on wildcard resources",
        "Delete, terminate, remove, or similar operations are allowed without resource scoping.", 16, i,
        destructive.join(", "), "Limit destructive operations to explicit resources and consider separate operational roles.");
      score += 16;
    }

    const broad = actions.includes("*") || serviceWildcards.length > 0 || resources.includes("*") || notActions.length > 0 || notResources.length > 0;
    if (isAllow && broad && !hasCondition) {
      add(findings, `no-condition-${i}`, "medium", "Broad allow statement has no conditions",
        "There are no contextual restrictions such as source network, tags, region, or MFA-related conditions.", 8, i,
        "Condition: not present", "Where appropriate, add conditions that constrain how, where, or by whom permissions can be used.");
      score += 8;
    }

    if ((s.Effect || "").toLowerCase() === "deny") {
      add(findings, `deny-${i}`, "info", "Explicit deny present",
        "An explicit Deny can act as a guardrail, though its effectiveness depends on its scope and conditions.", 0, i, `Statement ${i + 1}`);
    }

    const shownActions = actions.length ? actions : notActions.map(a => `NOT ${a}`);
    const shownResources = resources.length ? resources : notResources.map(r => `NOT ${r}`);
    statementAnalyses.push({
      index: i, sid: s.Sid, effect: s.Effect || "Unknown", actions: shownActions, resources: shownResources,
      services: uniq([...actions, ...notActions].map(serviceOf)), hasCondition,
      score: Math.min(score, 100), riskLabel: labelFor(Math.min(score, 100)),
    });
  });

  if (!findings.length && !structuralErrors.length) {
    add(findings, "no-obvious-risk", "low", "No obvious broad-permission pattern detected",
      "The configured static rules did not find a broad-permission pattern. This does not prove the policy is least-privilege or safe.", 0,
      undefined, undefined, "Review the policy in its real identity, resource-policy, SCP, permissions-boundary, and session-policy context.");
  }

  const serviceMap = new Map<string, Set<string>>();
  statementAnalyses.forEach(s => s.actions.forEach(action => {
    const rawAction = action.replace(/^NOT\s+/, "");
    const service = serviceOf(rawAction);
    if (!serviceMap.has(service)) serviceMap.set(service, new Set());
    serviceMap.get(service)!.add(action);
  }));
  const services = [...serviceMap.entries()].map(([service, actions]) => ({ service, actions: [...actions].sort() }))
    .sort((a, b) => b.actions.length - a.actions.length || a.service.localeCompare(b.service));

  const score = Math.min(findings.reduce((sum, f) => sum + f.score, 0), 100);
  const uniqueActions = uniq(statementAnalyses.flatMap(s => s.actions));
  const uniqueResources = uniq(statementAnalyses.flatMap(s => s.resources));

  return {
    structuralErrors, score, riskLabel: labelFor(score),
    findings: [...findings].sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]),
    statements: statementAnalyses, services,
    summary: {
      statements: statementAnalyses.length, services: services.length, actions: uniqueActions.length,
      resources: uniqueResources.length,
      critical: findings.filter(f => f.severity === "critical").length,
      high: findings.filter(f => f.severity === "high").length,
    },
  };
}
