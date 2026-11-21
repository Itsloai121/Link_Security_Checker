# Universal Project Directory & File Architecture (UPDA)

**Version:** 1.0  
**Purpose:** A reusable, technology-independent repository structure for web, desktop, mobile, API, CLI, SaaS, and other software projects.

> Create only the folders your project uses. Items marked **(optional)** are not required. Replace `<module>` with a real business or feature module name. Framework-specific conventions may override this layout.

## 1. Universal directory schema

```text
project-root/
│
├── .github/                              # Repository automation and collaboration rules
│   ├── workflows/                        # CI checks, tests, builds, and release workflows
│   ├── ISSUE_TEMPLATE/                   # Standard issue-report templates (optional)
│   └── PULL_REQUEST_TEMPLATE.md          # Pull-request checklist (optional)
│
├── docs/                                 # Human-readable project documentation
│   ├── architecture/                     # Architecture descriptions and diagrams
│   │   ├── overview.md                   # High-level system structure and boundaries
│   │   ├── backend.md                    # Backend design reference
│   │   ├── data.md                       # Data model, ownership, and lifecycle reference
│   │   ├── security.md                   # Security architecture and controls reference
│   │   └── decisions/                    # Architecture Decision Records (ADRs)
│   ├── api/                              # API specifications and usage documentation
│   ├── development/                      # Setup, coding, and contribution guides
│   └── operations/                       # Deployment, maintenance, recovery, and runbooks
│
├── src/                                  # All application source code
│   ├── bootstrap/                        # Starts the application and assembles its components
│   │   ├── main.<ext>                    # Main executable entry point
│   │   └── dependency_wiring.<ext>       # Connects interfaces to their implementations
│   │
│   ├── modules/                          # Independent business capabilities or feature areas
│   │   └── <module>/                     # Example: accounts, billing, reports, projects
│   │       ├── domain/                   # Core business entities, rules, and value objects
│   │       ├── application/               # Use cases, workflows, and application services
│   │       ├── ports/                    # Interfaces the module needs or exposes
│   │       └── infrastructure/           # Module-specific database and external adapters
│   │
│   ├── interfaces/                       # Ways users or other systems interact with the app
│   │   ├── api/                          # HTTP or other API entry points
│   │   │   ├── routes/                   # Endpoint and route definitions
│   │   │   ├── handlers/                 # Converts requests into application calls
│   │   │   ├── schemas/                  # Request and response data structures
│   │   │   └── middleware/               # Shared request-processing components
│   │   ├── web/                          # Browser-based user interface (optional)
│   │   │   ├── pages/                    # Pages or route-level screens
│   │   │   ├── components/               # Reusable visual components
│   │   │   ├── state/                    # Client-side state management
│   │   │   └── api_client/               # Frontend code for communicating with APIs
│   │   ├── desktop/                      # Desktop GUI entry points and presentation (optional)
│   │   ├── mobile/                       # Mobile app presentation and entry points (optional)
│   │   ├── cli/                          # Command-line interface (optional)
│   │   ├── webhooks/                     # Incoming webhook handlers (optional)
│   │   └── events/                       # Incoming event or message consumers (optional)
│   │
│   ├── workers/                          # Background jobs and scheduled task execution
│   │   ├── handlers/                     # Job processing functions
│   │   └── schedules/                    # Recurring task definitions
│   │
│   ├── infrastructure/                  # Shared technical adapters and integrations
│   │   ├── persistence/                  # Database connections and shared persistence tools
│   │   ├── messaging/                    # Message broker and event-bus adapters
│   │   ├── cache/                        # Cache clients and cache policies
│   │   ├── external_services/            # Third-party service clients
│   │   └── observability/                # Logging, metrics, and tracing integrations
│   │
│   └── shared/                           # Small, genuinely reusable cross-module code
│       ├── errors/                       # Shared error types and handling primitives
│       ├── contracts/                    # Shared types and interface contracts
│       └── utilities/                    # General-purpose helpers with no business ownership
│
├── tests/                                # Automated tests
│   ├── unit/                             # Tests for isolated functions and components
│   ├── integration/                      # Tests across modules, databases, and services
│   ├── contract/                         # Tests that verify API and service agreements
│   ├── end_to_end/                       # Tests of complete user or system workflows
│   ├── security/                         # Security-focused tests and regression cases
│   ├── performance/                      # Load, stress, and performance tests (optional)
│   └── fixtures/                         # Safe sample data used by tests
│
├── migrations/                           # Versioned database and data-schema changes
│
├── config/                               # Non-secret application configuration
│   ├── defaults/                         # Safe default configuration values
│   └── schemas/                          # Rules for validating configuration files
│
├── scripts/                              # Repeatable development, maintenance, and admin scripts
│
├── infra/                                # Infrastructure and deployment definitions (optional)
│   ├── containers/                       # Container build files and related configuration
│   ├── iac/                              # Infrastructure-as-Code definitions
│   └── environments/                     # Environment-specific deployment templates
│
├── assets/                               # Static files shipped with the application (optional)
│   ├── images/                           # Images and icons
│   ├── fonts/                            # Application fonts
│   └── templates/                        # Email, document, or export templates
│
├── data/                                 # Safe, version-controlled reference or seed data only (optional)
│   ├── seeds/                            # Initial records for development or test environments
│   └── samples/                          # Small, non-sensitive example datasets
│
├── examples/                             # Small examples showing how to use the project (optional)
├── tools/                                # Project-specific developer utilities (optional)
│
├── .env.example                          # Names and example values of required environment variables
├── .gitignore                            # Files and folders Git must not track
├── .dockerignore                         # Files excluded from container build context (optional)
├── .editorconfig                         # Consistent editor and formatting defaults
├── README.md                             # Project purpose, setup, usage, and quick start
├── CONTRIBUTING.md                       # Rules for contributing and submitting changes (optional)
├── CHANGELOG.md                          # Notable changes between project versions
├── LICENSE                               # Project license and usage terms
├── <language-project-manifest>           # Language/framework project definition and dependencies
└── <dependency-lockfile>                 # Exact resolved dependency versions, when supported
```

## 2. Key placement rules

| Item | Put it here | Function |
|---|---|---|
| Application startup | `src/bootstrap/` | Starts the application and wires components together |
| Feature/business logic | `src/modules/<module>/` | Keeps each business capability organized and isolated |
| User and system entry points | `src/interfaces/` | Handles web, API, desktop, mobile, CLI, webhook, and event inputs |
| Background execution | `src/workers/` | Runs jobs outside the normal request or interaction flow |
| Shared technical integrations | `src/infrastructure/` | Connects the application to databases, queues, caches, and providers |
| Cross-module helpers | `src/shared/` | Holds only code genuinely reused across modules |
| Automated verification | `tests/` | Holds unit, integration, contract, end-to-end, and security tests |
| Database structure changes | `migrations/` | Tracks schema changes in a repeatable, ordered way |
| Non-secret settings | `config/` | Stores defaults and configuration validation rules |
| Repeatable commands | `scripts/` | Automates setup, checks, maintenance, and administrative tasks |
| Deployment definitions | `infra/` | Describes containers and infrastructure provisioning |
| Documentation | `docs/` | Explains architecture, APIs, development, and operations |

## 3. Module internal structure

Use this structure for each meaningful feature or business capability:

```text
src/modules/<module>/
├── domain/                 # Business rules; independent of frameworks and databases
├── application/             # Use cases and workflows that coordinate domain behavior
├── ports/                   # Interfaces for required or provided capabilities
└── infrastructure/          # Concrete implementations of module ports
```

**Dependency direction:** `interfaces` call `application`; `application` uses `domain` and `ports`; `infrastructure` implements ports. Keep domain rules independent from UI frameworks, databases, and external providers.

## 4. Files that should not be committed

```text
.env                         # Real secrets and machine-specific settings
.venv/                       # Local language environment
node_modules/                # Installed dependency directory
__pycache__/                 # Python runtime cache
.pytest_cache/               # Test cache
coverage/                    # Generated coverage output
build/                       # Generated build output
dist/                        # Generated distribution output
logs/                        # Runtime logs
tmp/                         # Temporary runtime files
uploads/                     # User-uploaded runtime content
```

Add applicable entries to `.gitignore`. Store production uploads, logs, secrets, databases, and other runtime-generated data in appropriate external or managed storage—not in the source repository.

## 5. Adaptation rules

1. Keep the root structure consistent across projects.
2. Add only the interfaces the project actually needs (web, API, desktop, mobile, CLI, or events).
3. Create a module for each meaningful business capability; do not create a module for every small function.
4. Keep business logic inside its owning module, not in `shared/`.
5. Keep credentials and real environment secrets out of source control.
6. Keep generated files, local environments, runtime data, and user uploads out of the repository.
7. Follow the chosen language and framework's required conventions where they conflict with this generic template.
8. For a small project, combine or omit unnecessary folders rather than creating empty structure.

**Core rule:** Organize code by responsibility and business capability. Keep entry points, business rules, technical integrations, tests, configuration, and documentation clearly separated.
