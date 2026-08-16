# PolicyScope — IAM Policy Risk Explorer

A frontend-only AWS IAM policy analyzer that visualizes permissions, detects risky patterns, and explains policy statements in a human-friendly interface.

## Tech stack

- React
- TypeScript
- Vite
- Tailwind CSS
- Browser `localStorage`

No backend, AWS account, credentials, database, API, chart library, or component library is required.

## Features

- Paste and analyze IAM policy JSON
- JSON syntax validation
- Basic IAM policy structure checks
- 0–100 heuristic risk score
- Critical / high / medium / low findings
- Wildcard action detection
- Service wildcard detection (`s3:*`, `iam:*`, etc.)
- Wildcard resource and Principal detection
- Sensitive privilege-escalation action detection
- Destructive wildcard permission detection
- `NotAction` and `NotResource` warnings
- Missing-condition warnings on broad Allow statements
- Permission grouping by AWS service
- Human-friendly statement cards
- Example policies
- Browser persistence
- JSON analysis export
- Responsive UI

## Run locally

Vite 8 requires Node.js 20.19+ or 22.12+.

```bash
npm install
npm run dev
```

## Production build

```bash
npm run build
npm run preview
```

## Architecture

```text
IAM policy JSON
      |
      v
JSON parser
      |
      v
Static validation
      |
      v
Rules engine (src/analyzer.ts)
      |
      +----> Risk score
      +----> Security findings
      +----> Permission map
      +----> Statement analysis
```

## Important disclaimer

PolicyScope is an educational static analyzer. It is **not AWS IAM Access Analyzer** and it does not make authoritative authorization decisions.

Effective AWS permissions can also depend on resource-based policies, AWS Organizations SCPs, permissions boundaries, session policies, explicit denies, service-specific authorization behavior, and request context.

## Next milestones

- Current vs improved policy comparison
- Finding search and filters
- Condition visualizer
- Resource ARN grouping
- Policy diff viewer
- Configurable static rules
- Unit tests for the analyzer
- GitHub Pages deployment workflow
