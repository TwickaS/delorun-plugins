/**
 * The release-candidate seed the coverage ledger starts from: one unit for each boundary of section
 * "Boundaries and their defences" in Delorun's threat model. A unit names the boundary as the page writes it, the
 * package that implements the defence, the ordinary attack class the skill assigns and the paths a hunter starts
 * from, so an audit of a release candidate leaves out no boundary the project claims to protect. The seed is a
 * starting point: reconnaissance and the coverage critic add the combinations it does not name.
 * @module delorun-plugin-security-audit/rc-profile
 */
import type { UnitSeed } from './types.ts'

/** The threat model's repository-relative path, which every surface reference names. */
const THREAT_MODEL = 'delorun/docs/security/threat-model.md'

/** The header a block reference from the skill pack carries. */
const ATTACK_CLASSES = 'ATTACK-CLASSES.md'

/** One boundary of the threat model and the source that implements its defence. */
interface Boundary {
  /** The section heading under "Boundaries and their defences", verbatim. */
  readonly boundary: string
  /** The surface through which a person or a program reaches the boundary. */
  readonly surface: string
  /** The repository-relative package the defence lives in. */
  readonly subsystem: string
  /** The ordinary attack class from `ATTACK-CLASSES.md` that the boundary's evidence answers. */
  readonly attack_class: string
  /** Repository-relative paths a hunter starts from; the package the boundary lives in comes first. */
  readonly starting_paths: readonly string[]
  /** The companion blocks the boundary's domain requires, beyond the companion sections they bring. */
  readonly companion_blocks: readonly string[]
  /** Blocks considered and left out, each with the source fact that excludes it. */
  readonly excluded_blocks: readonly { readonly block: string; readonly reason: string }[]
}

/**
 * The sixteen boundaries of the threat model's "Boundaries and their defences", in the page's order.
 *
 * `surface` names what a person reaches; `subsystem` is the package that holds the defence. Where the page says a
 * defence is not built, the unit still exists, because the audit's question is also whether the code that ships
 * matches the claim: `Container isolation` and `The catalogue and revocation` name packages that exist and are
 * never reached by a shipped command, and `Parity` names the composition that switches Protections off.
 */
const BOUNDARIES: readonly Boundary[] = [
  {
    boundary: 'Confinement of native commands',
    surface: 'A command the CLI profile runs under read-only or workspace-write',
    subsystem: 'packages/sandbox/sandbox-local',
    attack_class: 'Access control',
    starting_paths: ['packages/sandbox/sandbox-local', 'packages/sandbox/sandbox-windows-acl', 'delorun/packages/bundle-local'],
    companion_blocks: [
      'DESKTOP-MOBILE-AND-LOCAL-IPC.md#Local IPC and exported-component attack classes',
      'DESKTOP-MOBILE-AND-LOCAL-IPC.md#Privileged-helper and local-file attack classes',
    ],
    excluded_blocks: [
      { block: 'ATTACK-CLASSES.md#Injection', reason: 'the boundary confines reads, writes and socket connections; it parses no untrusted text into a sink' },
      { block: 'CLOUD-AND-DEPLOYMENT.md#Container and orchestration attack classes', reason: 'the rules apply to commands on the host; Docker workspaces are the next boundary' },
    ],
  },
  {
    boundary: "The home's control channels",
    surface: "A caller holding the start token on the home's update.sock",
    subsystem: 'delorun/packages/home-process',
    attack_class: 'Access control',
    starting_paths: ['delorun/packages/home-process', 'delorun/packages/contract-home-process'],
    companion_blocks: [
      'PROTOCOLS-RPC-AND-MESSAGING.md#RPC identity and authorization attack classes',
      'PROTOCOLS-RPC-AND-MESSAGING.md#Replay, ordering, and transaction attack classes',
    ],
    excluded_blocks: [
      { block: 'ATTACK-CLASSES.md#Injection', reason: 'a request carries no path, archive, URL or command, so the channel chooses a version and passes no text through' },
    ],
  },
  {
    boundary: 'Container isolation',
    surface: 'The supervisor that would start and confine a Docker workspace',
    subsystem: 'delorun/packages/supervisor',
    attack_class: 'Access control',
    starting_paths: ['delorun/packages/supervisor', 'delorun/packages/contract-runtime-supervisor'],
    companion_blocks: ['CLOUD-AND-DEPLOYMENT.md#Container and orchestration attack classes'],
    excluded_blocks: [
      { block: 'CLOUD-AND-DEPLOYMENT.md#Workload identity and IAM attack classes', reason: 'a workspace container holds no cloud identity; the supervisor starts it on the person\u2019s own machine' },
    ],
  },
  {
    boundary: 'Admission and listeners',
    surface: "The studio's loopback listener and its launch token",
    subsystem: 'delorun/packages/contract-admission',
    attack_class: 'Access control',
    starting_paths: ['delorun/packages/contract-admission', 'delorun/packages/home-auth'],
    companion_blocks: [
      'WEB-PROTOCOL-AND-AUTH.md#Browser-session attack classes',
      'WEB-PROTOCOL-AND-AUTH.md#HTTP framing and cache attack classes',
    ],
    excluded_blocks: [
      { block: 'WEB-PROTOCOL-AND-AUTH.md#Federated-identity attack classes', reason: 'Delorun builds no OpenID Connect provider, so the loopback listener admits no federated identity' },
    ],
  },
  {
    boundary: 'Device approval',
    surface: "The approval window at the home's computer and its match code",
    subsystem: 'delorun/packages/home-auth',
    attack_class: 'Business logic',
    starting_paths: ['delorun/packages/home-auth', 'delorun/packages/contract-device-approval', 'delorun/apps/cli/src/devices'],
    companion_blocks: ['WEB-PROTOCOL-AND-AUTH.md#MFA, passkey, and account-transition attack classes'],
    excluded_blocks: [
      { block: 'WEB-PROTOCOL-AND-AUTH.md#Federated-identity attack classes', reason: 'an approval is bound to a match code the person reads at the computer, not to an identity provider' },
    ],
  },
  {
    boundary: 'Reach providers',
    surface: 'The Tailscale private route served through tailscale serve',
    subsystem: 'delorun/packages/reach',
    attack_class: 'Business logic',
    starting_paths: ['delorun/packages/reach', 'delorun/apps/cli/src/reach'],
    companion_blocks: ['CLOUD-AND-DEPLOYMENT.md#Ingress, network, and control-plane attack classes'],
    excluded_blocks: [
      { block: 'CLOUD-AND-DEPLOYMENT.md#Managed storage, events, and edge attack classes', reason: 'the provider stores nothing and handles no events; it serves one local port and removes the serve rules it does not own' },
    ],
  },
  {
    boundary: 'Sign-in',
    surface: "The sign-in page and the launch token that opens it",
    subsystem: 'delorun/packages/home-auth',
    attack_class: 'Access control',
    starting_paths: ['delorun/packages/home-auth', 'delorun/packages/contract-oidc-passkeys'],
    companion_blocks: ['WEB-PROTOCOL-AND-AUTH.md#Browser-session attack classes'],
    excluded_blocks: [
      { block: 'WEB-PROTOCOL-AND-AUTH.md#MFA, passkey, and account-transition attack classes', reason: 'passkeys, the recovery kit and reset are not built, so a session is admitted by a launch token or an approved device key alone' },
    ],
  },
  {
    boundary: 'Releases, the log and the rebuild',
    surface: 'Signing a release and verifying its entry in the release log',
    subsystem: 'delorun/apps/release',
    attack_class: 'Cryptography and secrets',
    starting_paths: ['delorun/apps/release', 'delorun/apps/npm-launcher', 'delorun/apps/release-channel', 'delorun/packages/release-formats'],
    companion_blocks: ['SUPPLY-CHAIN-AND-RELEASE.md#Release and update attack classes'],
    excluded_blocks: [
      { block: 'SUPPLY-CHAIN-AND-RELEASE.md#CI and automation attack classes', reason: 'no release workflow exists: the maintainer builds and signs releases on their own machine until 1.0' },
    ],
  },
  {
    boundary: 'The catalogue and revocation',
    surface: 'Listing a plugin version and refusing a revoked one',
    subsystem: 'delorun/packages/contract-catalogue-revocation',
    attack_class: 'Business logic',
    starting_paths: ['delorun/packages/contract-catalogue-revocation', 'delorun/packages/plugin-install-check'],
    companion_blocks: ['SUPPLY-CHAIN-AND-RELEASE.md#Dependency and build-input attack classes'],
    excluded_blocks: [
      { block: 'ATTACK-CLASSES.md#Injection', reason: 'an entry carries a package name, a version, a digest and version ranges, and no field reaches an interpreter' },
    ],
  },
  {
    boundary: 'Updates and rollback',
    surface: 'Applying an update and rolling it back',
    subsystem: 'delorun/packages/update',
    attack_class: 'Business logic',
    starting_paths: ['delorun/packages/update', 'delorun/apps/cli/src/update', 'delorun/apps/cli/src/recover.ts'],
    companion_blocks: [
      'SUPPLY-CHAIN-AND-RELEASE.md#Release and update attack classes',
      'RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Failure and recovery attack classes',
    ],
    excluded_blocks: [
      { block: 'ATTACK-CLASSES.md#Injection', reason: 'an update reads a signed manifest and the lockfile, shows the plan and installs nothing until the person confirms' },
    ],
  },
  {
    boundary: 'Archives and untrusted chats',
    surface: 'Importing an archive and emptying the trash',
    subsystem: 'delorun/packages/archive',
    attack_class: 'Feature abuse and data leakage',
    starting_paths: ['delorun/packages/archive', 'delorun/packages/trash', 'delorun/apps/cli/src/import'],
    companion_blocks: [
      'DATA-ISOLATION-AND-LIFECYCLE.md#Export, backup, restore, and migration attack classes',
      'DATA-ISOLATION-AND-LIFECYCLE.md#Deletion, revocation, and lifecycle attack classes',
    ],
    excluded_blocks: [
      { block: 'DATA-ISOLATION-AND-LIFECYCLE.md#Tenant and object-isolation attack classes', reason: 'a home holds one person, so an archive crosses no tenant' },
    ],
  },
  {
    boundary: 'Logs and redaction',
    surface: "Writing a record to the home's operational logs",
    subsystem: 'delorun/packages/logs',
    attack_class: 'Cryptography and secrets',
    starting_paths: ['delorun/packages/logs', 'delorun/packages/contract-operational-logs'],
    companion_blocks: ['DATA-ISOLATION-AND-LIFECYCLE.md#Derived-data and disclosure attack classes'],
    excluded_blocks: [
      { block: 'DATA-ISOLATION-AND-LIFECYCLE.md#Deletion, revocation, and lifecycle attack classes', reason: 'each invocation deletes logs written more than 14 days before by file age, so retention decides by date and not by what a record holds' },
    ],
  },
  {
    boundary: 'Verification',
    surface: 'The delorun verify command and the report it prints',
    subsystem: 'delorun/apps/cli',
    attack_class: 'Business logic',
    starting_paths: ['delorun/apps/cli/src/verify', 'delorun/packages/release-verify', 'delorun/packages/contract-verification-checks'],
    companion_blocks: ['SUPPLY-CHAIN-AND-RELEASE.md#Release and update attack classes'],
    excluded_blocks: [
      { block: 'ATTACK-CLASSES.md#Injection', reason: 'a check reads a signed file list and hashes files; it builds no prompt or query from what it reads' },
    ],
  },
  {
    boundary: 'Parity',
    surface: 'The parity composition overlay and its switches',
    subsystem: 'delorun/packages/contract-parity-composition',
    attack_class: 'Chained vulnerabilities and trust boundaries',
    starting_paths: ['delorun/packages/contract-parity-composition', 'delorun/apps/tools/src/parity/composition/parity.overlay.yml'],
    companion_blocks: [],
    excluded_blocks: [
      { block: 'CLOUD-AND-DEPLOYMENT.md#Configuration and secret lifecycle attack classes', reason: 'the overlay switches rows on and off and carries no configuration value or secret' },
    ],
  },
  {
    boundary: 'The web_fetch guard',
    surface: "The web_fetch tool and the HTTP fetch provider's targets",
    subsystem: 'delorun/packages/plugin-fetch-guard',
    attack_class: 'Resource and file handling',
    starting_paths: ['delorun/packages/plugin-fetch-guard', 'packages/web/web-fetch-http', 'delorun/packages/bundle-local'],
    companion_blocks: ['CLOUD-AND-DEPLOYMENT.md#Ingress, network, and control-plane attack classes'],
    excluded_blocks: [
      { block: 'ATTACK-CLASSES.md#Injection', reason: 'the guard approves a host and the addresses it resolves to before a connection and follows each redirect, so the fetched body reaches no sink of its own' },
    ],
  },
  {
    boundary: 'Data sharing',
    surface: "The session-log upload switch and the network-request allowlist",
    subsystem: 'delorun/packages/bundle-local',
    attack_class: 'Feature abuse and data leakage',
    starting_paths: ['delorun/packages/bundle-local', 'delorun/packages/contract-setup-answers', 'delorun/apps/tools/src/checks/network-requests.json'],
    companion_blocks: ['DATA-ISOLATION-AND-LIFECYCLE.md#Derived-data and disclosure attack classes'],
    excluded_blocks: [
      { block: 'ATTACK-CLASSES.md#Injection', reason: 'the boundary decides which requests leave the machine; text that arrives from outside it is a boundary of its own' },
    ],
  },
]

/**
 * The coverage units a release-candidate run starts from: one for each boundary of the threat model, each planned
 * and unassigned, with the threat model's section heading as its canonical boundary.
 * @returns fresh unit seeds, in the threat model's order.
 */
export function rcSeedUnits(): UnitSeed[] {
  return BOUNDARIES.map(row => ({
    canonical_refs: {
      surface: row.subsystem + '#' + row.surface,
      boundary: row.boundary,
      subsystem: row.subsystem,
      attack_class: ATTACK_CLASSES + '#' + row.attack_class,
    },
    surface: row.surface + ' (' + row.subsystem + ', ' + THREAT_MODEL + ')',
    boundary: row.boundary,
    subsystem: row.subsystem,
    attack_class: row.attack_class,
    starting_paths: [...row.starting_paths],
    ordinary_attack_class_block: ATTACK_CLASSES + '#' + row.attack_class,
    selected_companion_blocks: [...row.companion_blocks],
    excluded_blocks: row.excluded_blocks.map(entry => ({ block: entry.block, reason: entry.reason })),
    prior_status: 'none',
  }))
}
