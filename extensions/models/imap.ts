/**
 * Provider-agnostic IMAP inspection + gated-write model.
 *
 * Wraps the `imapflow` IMAP client as a typed swamp primitive. It is NOT a
 * shell/CLI wrapper: every operation goes through the imapflow library behind a
 * single injectable client seam ({@link ClientFactory}), so unit tests inject a
 * synthetic in-memory client and no live server is ever contacted during a
 * build. It is generic and reusable for any IMAP mailbox over TLS (e.g.
 * user@example.com on imap.example.com:993).
 *
 * ## Transport and authentication
 *
 * TLS IMAP (`secure: true`, port 993 by default) via imapflow. The mailbox
 * credential is resolved from a swamp vault via a CEL expression on the
 * `password` global argument, e.g.
 *   --global-arg 'password=${{ vault.get("my-mailbox", "password") }}'
 * The credential is never inlined in the model definition. `host`, `port`,
 * `user`, and `secure` are plain (non-secret) connection settings.
 *
 * ## Read path (Phase 1; unchanged, still read-only)
 *
 *   - listFolders: enumerate the folder tree with per-folder message counts and
 *     sizes (IMAP STATUS; no mailbox is modified).
 *   - sync: open each requested mailbox with `readOnly: true` (IMAP EXAMINE, not
 *     SELECT) and fetch ENVELOPES and a fixed set of HEADERS ONLY -- never
 *     message bodies -- into a versioned snapshot resource.
 *   - fetchMessage: open ONE folder with `readOnly: true` (EXAMINE) and decode
 *     the FULL bodies of a UID set with postal-mime (a pure, injectable
 *     `_parse` seam), writing one `messageBody` record per UID (decoded
 *     text/html, attachment METADATA only, extracted links). A single folder
 *     per call is deliberate: an IMAP UID is unique only within one
 *     (folder,UIDVALIDITY), so the uidValidity guard and the {@link
 *     MAX_FETCH_UIDS} bound only mean something scoped to one mailbox. It uses
 *     TWO fan-out fetches, never a per-UID loop: (1) one `{uid,size}` fetch to
 *     partition the set against {@link MAX_BODY_BYTES} by the server's
 *     RFC822.SIZE, then (2) one `source` fetch for the UNDER-cap UIDs only. An
 *     OVER-cap UID's body is DELIBERATELY NOT pulled -- its record is
 *     `truncated: true`, `sourceBytes` = the server size, null bodies -- so the
 *     oversized source is never buffered and `truncated` honestly means "body
 *     withheld for size". This is the ONLY method that pulls bodies: it breaks
 *     sync's header-only invariant ON PURPOSE for a narrow purpose
 *     (classification review, human triage, link/footer/receipt extraction),
 *     while performing ZERO mutation. Each message's decode is isolated in a
 *     try/catch: a MIME-parse throw records that one UID with an `error` and
 *     null bodies and the batch continues. Opening EXAMINE guarantees the
 *     session is read-only (the server refuses mutation and never sets
 *     `\Seen`), so no `peek` knob is offered. Stored `html` is RAW and
 *     UNSANITIZED; sanitization is deferred to any future consumer. The
 *     `messageBody` resource has a FINITE (bounded) lifetime so third-party
 *     body content does not persist indefinitely.
 * Opening mailboxes with EXAMINE means the server itself refuses mutations
 * through this session, so these read methods stay structurally read-only, not
 * just read-only by convention.
 *
 * ## Write path (Phase 3; gated)
 *
 *   - addKeywords / removeKeywords: fan out ONE `messageFlagsAdd` /
 *     `messageFlagsRemove` call over an entire UID set (never a per-message
 *     loop), using imapflow's typed flag API (never a hand-built STORE string).
 *   - move: fan out ONE `messageMove` call over an entire UID set, via
 *     imapflow's typed move API.
 *
 * ### Open/close discipline (never trigger an implicit expunge)
 *
 * imapflow's `mailboxClose()` issues IMAP CLOSE, which implicit-EXPUNGEs any
 * `\Deleted` messages on a SELECTed (read-write) mailbox. To guarantee a write
 * method can never destroy mail another session flagged `\Deleted`, the open
 * discipline is split:
 *   - The dryRun preview, the 0-UID path, and the uidValidity-refused path all
 *     open the mailbox READ-ONLY (EXAMINE, `readOnly: true`) and close it with
 *     `mailboxClose()`. Under EXAMINE the server itself refuses mutations and
 *     CLOSE never expunges, so these structurally read-only paths are safe.
 *   - The mailbox is opened READ-WRITE only when `dryRun=false` AND there is
 *     something to change, and only via `getMailboxLock(path,{readOnly:false})`.
 *     It is released with `lock.release()`, which clears the lock WITHOUT
 *     issuing IMAP CLOSE/UNSELECT -- so no implicit expunge is ever triggered
 *     on the write path. `mailboxClose()` is never called on a read-write box.
 *
 * Every write method:
 *   - defaults `dryRun` to `true` in its zod schema; `dryRun=true` performs
 *     ZERO server mutation and only computes a `wouldAffect` preview.
 *     `dryRun=false` is the sole mutate path and is expected to be
 *     operationally gated outside this type.
 *   - refuses (throws, no mutation) if a caller-supplied `uidValidity` does
 *     not match the mailbox's live UIDVALIDITY, guarding against mutating a
 *     stale UID selection.
 *   - validates every keyword string against the IMAP atom grammar before
 *     doing anything else (see {@link validateKeyword}): rejects control
 *     characters, whitespace, atom-specials, non-ASCII (>=0x80), AND the entire
 *     system-flag namespace (any leading backslash, e.g. `\Deleted`, `\Seen`).
 *     These methods set CUSTOM keywords only (cat/, list/, vendor/, flag/...);
 *     system flags are out of P3 scope. Defense in depth on top of imapflow's
 *     typed encoding.
 *   - caps the UID set at {@link MAX_UIDS}, rejecting oversized requests with a
 *     batching hint so one fan-out command can never exceed IMAP line limits.
 *   - is idempotent: re-adding an already-present keyword, re-removing an
 *     already-absent one, or re-moving a message no longer in the source
 *     folder is a recorded no-op, not a repeated mutation attempt.
 *   - records VERIFIED evidence on the mutate path: after the single fan-out
 *     command it re-FETCHes the affected UIDs and records the ACTUAL resulting
 *     state in `applied.items`, with a `discrepancies[]` listing any UID the
 *     server silently did not bring to its expected state.
 * `move` additionally distinguishes UIDs it actually moved from UIDs that were
 * absent from the source folder (`missingFromSource` -- an anomaly a human must
 * review: expunged or moved elsewhere, NOT confirmed converged), and rejects a
 * self-move (`destination === folder`).
 * copy/expunge/delete beyond this scope remain out of scope for this phase
 * (see the P3 build spec).
 *
 * ## Plan-driven write path (Reconcile-B; gated)
 *
 *   - applyTagPlan: reads the LATEST `tagPlan` record from a named
 *     `@shrug/mail-ontology` model instance (via `readModelData`; it never
 *     recomputes classification -- repo rule 3) and applies it in two
 *     fan-outs: ONE addKeywords-equivalent STORE per distinct
 *     (folder,keyword) group, and ONE move-equivalent MOVE per distinct
 *     (folder,destination) group -- never a per-message loop. Every group
 *     goes through the SAME two-phase safety core addKeywords/removeKeywords/
 *     move use (EXAMINE inspect, uidValidity + drift guard, read-write lock
 *     released WITHOUT CLOSE, post-mutation re-FETCH verification); a group
 *     over {@link MAX_UIDS} is chunked into multiple fan-out calls rather
 *     than rejected. Every tagPlan keyword is re-validated via
 *     {@link validateKeyword} before any connection is made -- one invalid
 *     keyword aborts the whole run rather than silently dropping it.
 *
 * ## Folder-creation write path (gated)
 *
 *   - createFolder: fans out over an entire LIST of mailbox paths in ONE
 *     call (never N per-folder calls), ensuring each exists. This is a
 *     mailbox-level op, not a per-UID one, so it needs none of the
 *     getMailboxLock/uidValidity machinery above -- its "inspect" phase is a
 *     single IMAP LIST (see {@link listFolderPaths}), not mailboxOpen/
 *     EXAMINE. Every path is validated (see {@link validateFolderPath}:
 *     non-empty, no leading/trailing whitespace, no control characters)
 *     before any connection is made, and the batch is capped at
 *     {@link MAX_FOLDERS}. `dryRun=true` (default) performs ZERO mutation:
 *     it reports, per folder, whether it already exists or would be created,
 *     using the server's LIVE hierarchy delimiter from LIST (never
 *     hardcoded). `dryRun=false` calls imapflow `mailboxCreate` for each
 *     ABSENT folder only (an already-present folder is skipped -- no create
 *     call at all). imapflow's own CREATE handler already treats an
 *     ALREADYEXISTS server response as success (`created: false`, not a
 *     thrown error); {@link isAlreadyExistsError} is defense-in-depth for a
 *     client that throws anyway. Because imapflow's `normalizePath` prepends
 *     the connection's namespace prefix and BOTH `list()` and
 *     `mailboxCreate()` return that normalized path, each item records the
 *     server-CANONICAL path (`resp.path`) and the post-creation re-LIST
 *     compares on THAT, not the raw request -- so a successful create under
 *     a non-empty namespace prefix is never misreported as a discrepancy.
 *     After creating, every requested folder is re-verified against a fresh
 *     LIST, and any folder still absent is recorded under `discrepancies[]`
 *     -- the create-call's own report is never trusted alone. BOTH a
 *     mailboxCreate failure mid-batch (not ALREADYEXISTS) AND a Phase-2
 *     re-LIST/verification failure persist the folders already processed
 *     plus the error before rethrowing, mirroring applyTagPlan's NEW-2 fix
 *     (the audit is never left empty on throw, even for live mutations
 *     already applied).
 *
 * @module
 */
import { z } from "npm:zod@4";
import { ImapFlow } from "npm:imapflow@2.2.1";
import PostalMime from "npm:postal-mime@2.7.2";

// ---------------------------------------------------------------------------
// Global arguments (connection + vaulted credential)
// ---------------------------------------------------------------------------

/** Connection and authentication settings for one IMAP mailbox. */
const GlobalArgsSchema = z.object({
  host: z
    .string()
    .min(1)
    .describe("IMAP server hostname, e.g. imap.example.com"),
  port: z
    .number()
    .int()
    .min(1)
    .max(65535)
    .default(993)
    .describe("IMAP server port (993 for implicit TLS)"),
  user: z
    .string()
    .min(1)
    .describe("Mailbox login, e.g. user@example.com"),
  password: z
    .string()
    .meta({ sensitive: true })
    .describe(
      "Mailbox password/app-password. Resolve from a swamp vault via CEL; " +
        'e.g. ${{ vault.get("my-mailbox", "password") }}. Never inline it.',
    ),
  secure: z
    .boolean()
    .default(true)
    .describe(
      "Use implicit TLS (true for port 993). Setting false uses opportunistic " +
        "STARTTLS, which is NOT fail-closed; it is rejected unless " +
        "allowInsecure is also set.",
    ),
  allowInsecure: z
    .boolean()
    .default(false)
    .describe(
      "Must be true to permit secure=false. Guards against accidentally " +
        "sending the mailbox credential over a connection that may not be " +
        "TLS-protected. Leave false in normal (implicit-TLS) deployments.",
    ),
  defaultFolder: z
    .string()
    .default("INBOX")
    .describe("Folder scanned by `sync` when none is given"),
});

/** Resolved connection and authentication settings. */
export type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

// ---------------------------------------------------------------------------
// Resource schemas
// ---------------------------------------------------------------------------

/** One parsed email address (display name + address, either may be null). */
const AddressSchema = z.object({
  name: z.string().nullable(),
  address: z.string().nullable(),
});

/** A normalized, header-and-envelope-only message record (NO body). */
const MessageSchema = z.object({
  uid: z.number().int().nullable(),
  folder: z.string(),
  from: z.array(AddressSchema),
  to: z.array(AddressSchema),
  cc: z.array(AddressSchema),
  subject: z.string().nullable(),
  date: z.string().nullable(),
  messageId: z.string().nullable(),
  inReplyTo: z.string().nullable(),
  references: z.string().nullable(),
  listId: z.string().nullable(),
  listUnsubscribe: z.string().nullable(),
  listPost: z.string().nullable(),
  replyTo: z.string().nullable(),
  autoSubmitted: z.string().nullable(),
  precedence: z.string().nullable(),
  flags: z.array(z.string()),
  size: z.number().int().nullable(),
});

/** A normalized message record. */
export type Message = z.infer<typeof MessageSchema>;

/** A snapshot of header/envelope records from one folder. */
const SnapshotSchema = z.object({
  folder: z.string(),
  scope: z.string().describe("What produced this snapshot, e.g. the folder"),
  count: z.number().int(),
  headersOnly: z.literal(true).describe("Proof that no bodies were fetched"),
  messages: z.array(MessageSchema),
  retrievedAt: z.iso.datetime(),
});

/**
 * One decoded attachment, METADATA ONLY. The attachment's raw content is
 * never fetched/stored (out of scope) -- only its descriptor plus byte `size`.
 */
const AttachmentSchema = z.object({
  filename: z.string().nullable(),
  contentType: z.string().nullable(),
  size: z.number().int().nullable(),
  contentId: z.string().nullable().optional(),
});

/**
 * A decoded full-body message record produced by `fetchMessage`. Carries the
 * SAME header/envelope fields `sync` produces (via {@link normalizeMessage}),
 * plus the decoded body: `text` / `html` (nullable), attachment METADATA only,
 * extracted `links`, and the truncation witnesses `truncated` + `sourceBytes`.
 * This is the ONE place this type persists message BODIES (sync never does).
 */
const MessageBodySchema = MessageSchema.extend({
  text: z.string().nullable().describe("Decoded text/plain part, or null"),
  html: z.string().nullable().describe("Decoded text/html part, or null"),
  attachments: z.array(AttachmentSchema).describe(
    "Attachment metadata ONLY (filename, contentType, size, contentId); the " +
      "attachment content itself is never fetched or stored",
  ),
  links: z.array(z.string()).describe(
    "http/https URLs extracted from BOTH the decoded text AND html, " +
      "de-duplicated in first-seen order (a heuristic; see extractLinks)",
  ),
  truncated: z.boolean().describe(
    "true when the body was withheld or capped for size: either the server's " +
      "RFC822.SIZE exceeded MAX_BODY_BYTES (body deliberately NOT pulled; " +
      "text/html null) or a no-server-size message's actual source exceeded " +
      "the cap (text/html byte-truncated). false otherwise.",
  ),
  sourceBytes: z.number().int().describe(
    "The raw source byte length -- the server's RFC822.SIZE for a withheld " +
      "over-cap message, else the actual fetched source length -- recorded " +
      "even when truncated so the truncation is never silent",
  ),
  error: z.string().nullable().describe(
    "Set to the error message when decoding THIS message threw (malformed or " +
      "hostile MIME); null on success. One bad message never aborts the batch.",
  ),
  retrievedAt: z.iso.datetime(),
});

/** A decoded full-body message record. */
export type MessageBody = z.infer<typeof MessageBodySchema>;

/** One folder's descriptor plus its message count and total size. */
const FolderSchema = z.object({
  path: z.string(),
  name: z.string().nullable(),
  delimiter: z.string().nullable(),
  flags: z.array(z.string()),
  subscribed: z.boolean().nullable(),
  messages: z.number().int().nullable(),
  size: z.number().int().nullable(),
});

/** The folder tree with aggregate counts. */
const FolderTreeSchema = z.object({
  totalFolders: z.number().int(),
  totalMessages: z.number().int(),
  folders: z.array(FolderSchema),
  retrievedAt: z.iso.datetime(),
});

/** One keyword-op (addKeywords/removeKeywords) per-UID preview/result row. */
const KeywordItemSchema = z.object({
  uid: z.number().int(),
  folder: z.string(),
  before: z.array(z.string()),
  after: z.array(z.string()),
});

/** One move per-UID preview/result row. */
const MoveItemSchema = z.object({
  uid: z.number().int(),
  from: z.string(),
  to: z.string(),
});

/** One UID a write method chose NOT to act on, and why. */
const SkippedItemSchema = z.object({
  uid: z.number().int(),
  reason: z.string(),
});

/**
 * One UID whose post-mutation re-FETCH did not match the expected after-state
 * (the server silently skipped it). Recorded only on the `dryRun=false` mutate
 * path, where `applied.items` carries the actual (re-fetched) state.
 */
const DiscrepancyItemSchema = z.object({
  uid: z.number().int(),
  reason: z.string(),
  expected: z.array(z.string()).optional(),
  actual: z.array(z.string()).optional(),
});

/**
 * A dry-run (`dryRun=true`, the default) preview of a write method's effect.
 * Emitted instead of mutating anything -- `dryRun=true` performs ZERO server
 * mutation. Echoes `folder` + `uidValidity` + the resolved UID counts so a
 * human can verify the target before any `dryRun=false` run (verify-before-
 * write).
 */
const WouldAffectSchema = z.object({
  op: z.enum(["addKeywords", "removeKeywords", "move"]),
  folder: z.string(),
  destination: z.string().optional(),
  uidValidity: z.number().int().nullable(),
  dryRun: z.literal(true),
  requestedCount: z.number().int().describe("Distinct UIDs requested"),
  resolvedCount: z.number().int().describe(
    "Of those, how many currently exist on the server",
  ),
  count: z.number().int().describe(
    "Of the resolved UIDs, how many would actually change (new-count)",
  ),
  items: z.array(z.union([KeywordItemSchema, MoveItemSchema])),
  skipped: z.array(SkippedItemSchema),
  missingFromSource: z.array(SkippedItemSchema).describe(
    "move only: requested UIDs absent from the source folder -- an anomaly " +
      "(expunged or moved elsewhere; NOT confirmed converged in destination). " +
      "Empty for keyword ops.",
  ),
  retrievedAt: z.iso.datetime(),
});

/** The result of a write method executed with `dryRun=false` (the only mutate path). */
const AppliedSchema = z.object({
  op: z.enum(["addKeywords", "removeKeywords", "move"]),
  folder: z.string(),
  destination: z.string().optional(),
  uidValidity: z.number().int().nullable(),
  requestedCount: z.number().int(),
  resolvedCount: z.number().int(),
  applied: z.number().int(),
  skipped: z.array(SkippedItemSchema),
  missingFromSource: z.array(SkippedItemSchema).describe(
    "move only: requested UIDs absent from the source folder (anomaly). " +
      "Empty for keyword ops.",
  ),
  items: z.array(z.union([KeywordItemSchema, MoveItemSchema])),
  discrepancies: z.array(DiscrepancyItemSchema).describe(
    "UIDs whose post-mutation re-FETCH did not reach the expected state " +
      "(server silently skipped them). Empty when every UID converged.",
  ),
  serverResponses: z.array(z.unknown()),
  error: z.string().optional().describe(
    "Set only on the partial-failure evidence written when the fan-out " +
      "command threw after being transmitted (CORR-4).",
  ),
  retrievedAt: z.iso.datetime(),
});

/** One requested folder's existence state in a createFolder preview. */
const CreateFolderPlanItemSchema = z.object({
  folder: z.string(),
  existsAlready: z.boolean(),
  wouldCreate: z.boolean(),
});

/**
 * A dryRun=true (the default) preview of createFolder: ZERO mutation
 * performed. One row per requested folder marking whether it already exists
 * (no-op) or would be created. `delimiter` echoes the server's LIVE
 * hierarchy delimiter (from IMAP LIST) -- never hardcoded -- so a human can
 * verify the target before any dryRun=false run (verify-before-write).
 */
const CreateFolderPreviewSchema = z.object({
  dryRun: z.literal(true),
  delimiter: z.string().nullable(),
  requestedCount: z.number().int().describe("Distinct folders requested"),
  existingCount: z.number().int(),
  wouldCreateCount: z.number().int(),
  items: z.array(CreateFolderPlanItemSchema),
  retrievedAt: z.iso.datetime(),
});

/** One requested folder's createFolder dryRun=false outcome. */
const CreateFolderResultItemSchema = z.object({
  folder: z.string().describe("The path exactly as the caller requested it"),
  canonicalPath: z.string().describe(
    "The server-canonical path (imapflow-normalized: namespace prefix " +
      "applied, INBOX upper-cased) actually created/matched -- this, NOT " +
      "the raw request, is what the post-creation re-LIST is compared " +
      "against (CF-2). Equals `folder` when the server has no namespace " +
      "prefix.",
  ),
  existedBefore: z.boolean().describe(
    "Whether the Phase-1 pre-check LIST already showed this folder present. " +
      "Advisory only: under a non-empty namespace prefix the raw-vs-" +
      "canonical mismatch can make this false for a folder that in fact " +
      "exists -- harmless because the create then returns ALREADYEXISTS " +
      "(alreadyExisted=true).",
  ),
  created: z.boolean().describe(
    "true only if THIS call's mailboxCreate newly created the mailbox",
  ),
  alreadyExisted: z.boolean().describe(
    "true if the folder was already present before this call, or the " +
      "server reported ALREADYEXISTS on create (idempotent no-op, not an " +
      "error)",
  ),
  verifiedExists: z.boolean().describe(
    "Set by a post-creation re-LIST (compared on canonicalPath); false " +
      "means the folder is still absent despite being requested (a " +
      "discrepancy)",
  ),
});

/**
 * The result of createFolder executed with dryRun=false (the only mutate
 * path). Every requested folder gets exactly one row; `discrepancies` lists
 * any folder STILL absent after the post-creation re-verification -- the
 * createFolder analogue of the keyword/move methods' post-mutation re-FETCH.
 */
const CreateFolderResultSchema = z.object({
  dryRun: z.literal(false),
  delimiter: z.string().nullable(),
  requestedCount: z.number().int(),
  createdCount: z.number().int().describe(
    "Folders newly AND verifiably created by THIS call: created=true AND " +
      "confirmed present by the post-creation re-LIST (CF-5). Excludes " +
      "already-existing folders, ALREADYEXISTS no-ops, and any folder the " +
      "server claimed to create but the re-LIST could not confirm (those " +
      "appear in discrepancies[]). On the partial-failure (error) record " +
      "this is the pre-verification claim, since Phase-2 never ran.",
  ),
  alreadyExistedCount: z.number().int(),
  items: z.array(CreateFolderResultItemSchema),
  discrepancies: z.array(
    z.object({ folder: z.string(), reason: z.string() }),
  ).describe(
    "Requested folders still absent after the post-creation re-LIST " +
      "(compared on canonicalPath)",
  ),
  serverResponses: z.array(z.unknown()),
  error: z.string().optional().describe(
    "Set on the partial-failure evidence written BEFORE rethrow when " +
      "either (a) mailboxCreate threw for a non-ALREADYEXISTS reason " +
      "mid-batch, or (b) the Phase-2 re-LIST/verification itself threw " +
      "after folders were already created live (CF-1) -- in both cases it " +
      "carries the folders already processed plus the error, so live " +
      "mutations are never lost to an unrecorded exception (mirrors " +
      "applyTagPlan NEW-2).",
  ),
  retrievedAt: z.iso.datetime(),
});

/**
 * One `@shrug/mail-ontology` tagPlan entry: a message's sanitized IMAP
 * keyword atoms plus an advisory Finance-move destination. Mirrors that
 * extension's `tagPlan` resource shape; deliberately re-declared here (not
 * imported across the extension boundary) since the two packages talk only
 * through the swamp data layer.
 */
const TagPlanItemSchema = z.object({
  folder: z.string(),
  uid: z.number().int(),
  keywords: z.array(z.string()),
  financeMove: z.string().nullable(),
});

/**
 * Fields common to a (folder,keyword) group's preview and applied rows.
 * `uidValidityDiverged` (ATP-5): when a group was chunked across multiple
 * fan-out STOREs and the mailbox's UIDVALIDITY differed between chunks, the
 * single `uidValidity` row cannot represent the group faithfully; this flag
 * surfaces that rather than silently reporting only the first chunk's value.
 * `notFound` (ATP-1): UIDs the plan named for this (folder,keyword) group
 * that are NOT present in the folder -- counted PER group occurrence, the
 * keyword-side analogue of a move group's `missingFromSource` (a plan UID
 * that vanished from the mailbox, distinct from a genuine no-op).
 */
const TagPlanKeywordGroupPreviewSchema = z.object({
  folder: z.string(),
  keyword: z.string(),
  uidValidity: z.number().int().nullable(),
  uidValidityDiverged: z.boolean(),
  uidCount: z.number().int(),
  addCount: z.number().int(),
  alreadyPresentCount: z.number().int(),
  notFound: z.number().int(),
});

/** One (folder,keyword) group's dryRun=false applied row. */
const TagPlanKeywordGroupAppliedSchema = z.object({
  folder: z.string(),
  keyword: z.string(),
  uidValidity: z.number().int().nullable(),
  uidValidityDiverged: z.boolean(),
  uidCount: z.number().int(),
  appliedCount: z.number().int(),
  alreadyPresentCount: z.number().int(),
  notFound: z.number().int(),
  discrepancies: z.array(DiscrepancyItemSchema),
});

/** One (folder,destination) group's dryRun=true preview row. */
const TagPlanMoveGroupPreviewSchema = z.object({
  folder: z.string(),
  destination: z.string(),
  uidValidity: z.number().int().nullable(),
  uidValidityDiverged: z.boolean(),
  uidCount: z.number().int(),
  missingFromSource: z.number().int(),
});

/** One (folder,destination) group's dryRun=false applied row. */
const TagPlanMoveGroupAppliedSchema = z.object({
  folder: z.string(),
  destination: z.string(),
  uidValidity: z.number().int().nullable(),
  uidValidityDiverged: z.boolean(),
  uidCount: z.number().int(),
  appliedCount: z.number().int(),
  missingFromSource: z.number().int(),
  discrepancies: z.array(
    z.object({ uid: z.number().int(), reason: z.string() }),
  ),
});

/** Aggregate counts across every group in one applyTagPlan run. */
const TagPlanTotalsSchema = z.object({
  keywordGroupCount: z.number().int(),
  moveGroupCount: z.number().int(),
  added: z.number().int(),
  alreadyPresent: z.number().int(),
  notFound: z.number().int().describe(
    "Keyword-group UIDs named by the plan but absent from their folder " +
      "(summed across groups); the keyword analogue of missingFromSource.",
  ),
  moved: z.number().int(),
  missingFromSource: z.number().int(),
  discrepancies: z.number().int(),
});

/**
 * A consolidated dryRun=true preview of applying an entire tagPlan: ZERO
 * mutation, one row per (folder,keyword) and (folder,destination) group.
 * `droppedCount` (ATP-2) reports tagPlan entries the cross-model decode
 * discarded as structurally malformed, so drift against @shrug/mail-ontology
 * is visible rather than silent (0 when the plan is injected via the test
 * seam).
 */
const TagPlanPreviewSchema = z.object({
  generatedAt: z.iso.datetime(),
  ontologyModel: z.string(),
  dryRun: z.literal(true),
  droppedCount: z.number().int(),
  keywordGroups: z.array(TagPlanKeywordGroupPreviewSchema),
  moveGroups: z.array(TagPlanMoveGroupPreviewSchema),
  totals: TagPlanTotalsSchema,
});

/**
 * The consolidated dryRun=false evidence of having applied an entire tagPlan.
 * `error` (NEW-2) is set only on the PARTIAL evidence written when a group's
 * fan-out threw mid-run: it carries the groups that completed before the
 * throw plus the error message, so live mutations already applied to earlier
 * groups are never lost to an unrecorded exception.
 */
const TagPlanAppliedSchema = z.object({
  generatedAt: z.iso.datetime(),
  ontologyModel: z.string(),
  dryRun: z.literal(false),
  droppedCount: z.number().int(),
  keywordGroups: z.array(TagPlanKeywordGroupAppliedSchema),
  moveGroups: z.array(TagPlanMoveGroupAppliedSchema),
  totals: TagPlanTotalsSchema,
  error: z.string().optional().describe(
    "Set only on the partial-failure evidence written when a group's fan-out " +
      "command threw mid-run (NEW-2); carries completed groups + the error.",
  ),
});

// ---------------------------------------------------------------------------
// Client seam (the sole network boundary; injected in tests)
// ---------------------------------------------------------------------------

/** One mailbox entry as returned by the IMAP LIST command. */
export interface ListEntry {
  path: string;
  name?: string;
  delimiter?: string | false;
  flags?: Set<string> | string[];
  subscribed?: boolean;
}

/** STATUS results for a mailbox (counts and size). */
export interface MailboxStatus {
  messages?: number;
  size?: number;
}

/** Which STATUS fields to request (booleans, not values). */
export interface StatusQuery {
  messages?: boolean;
  size?: boolean;
}

/** The subset of an imapflow fetch result this model consumes. */
export interface FetchMessage {
  uid?: number;
  flags?: Set<string> | string[];
  size?: number;
  envelope?: {
    from?: Array<{ name?: string; address?: string }>;
    to?: Array<{ name?: string; address?: string }>;
    cc?: Array<{ name?: string; address?: string }>;
    subject?: string;
    date?: Date | string;
    messageId?: string;
    inReplyTo?: string;
  };
  headers?: Uint8Array | string;
  /**
   * The raw RFC822 message source, returned by imapflow for a `source: true`
   * fetch (BODY.PEEK[], so the fetch never sets `\Seen`). Consumed ONLY by
   * `fetchMessage` -- the header-only read path (`sync`) never requests it.
   */
  source?: Uint8Array | string;
}

/** Query shape passed to {@link ImapClientLike.fetch} (envelope + headers only). */
export interface FetchQuery {
  envelope?: boolean;
  flags?: boolean;
  size?: boolean;
  uid?: boolean;
  headers?: string[] | boolean;
  /**
   * Request the full RFC822 source (imapflow issues BODY.PEEK[], which peeks
   * and never sets `\Seen`). Set ONLY by `fetchMessage`; the client seam stays
   * a SINGLE `fetch` (no separate download/part method).
   */
  source?: boolean;
}

/**
 * The decoded MIME shape a {@link MimeParser} returns. Deliberately minimal:
 * the decoded text/html parts plus attachment METADATA ONLY. Attachment
 * `content` is NEVER carried here (out of scope; avoids huge blobs) -- only its
 * byte `size` is kept, so attachments remain visible without storing payloads.
 */
export interface ParsedMime {
  text?: string | null;
  html?: string | null;
  attachments: Array<{
    filename?: string | null;
    mimeType?: string | null;
    contentId?: string | null;
    /** Byte length of the decoded attachment content; the content is dropped. */
    size?: number;
  }>;
}

/**
 * A pure, injectable MIME decoder: raw RFC822 source in, a {@link ParsedMime}
 * out. Injected into `fetchMessage` via the hidden `_parse` seam (parallel to
 * `_client`) so unit tests feed synthetic source and execute the REAL decoder
 * with no network and no live mail.
 */
export type MimeParser = (source: Uint8Array | string) => Promise<ParsedMime>;

/**
 * Result of opening a mailbox (read-only or read-write). `uidValidity` is
 * surfaced as a plain `number` (imapflow reports it as a `bigint`; the
 * adapter in {@link defaultClientFactory} coerces it) so write methods can
 * compare it directly against a caller-supplied guard value.
 */
export interface MailboxOpenResult {
  exists?: number;
  uidValidity?: number;
}

/**
 * A held read-write mailbox lock (imapflow `getMailboxLock`). The mailbox is
 * SELECTed for the lock's lifetime; `exists`/`uidValidity` reflect that live
 * SELECT (imapflow reports `uidValidity` as a `bigint`; the adapter coerces it
 * to a plain `number`). {@link MailboxLock.release} relinquishes the lock
 * WITHOUT issuing IMAP CLOSE/UNSELECT -- so releasing never triggers an
 * implicit expunge of `\Deleted` messages, unlike {@link
 * ImapClientLike.mailboxClose}.
 */
export interface MailboxLock {
  release(): void;
  exists?: number;
  uidValidity?: number;
}

/**
 * The subset of the imapflow client this model depends on: the Phase 1
 * read-only surface (list/status/fetch under EXAMINE) plus the Phase 3 gated
 * write surface (typed flag + move APIs, used only when a method explicitly
 * opens the mailbox with `readOnly: false`). Every write method call below is
 * a single fan-out operation over a UID array, never a per-message loop, and
 * never a hand-built STORE/MOVE command string.
 */
export interface ImapClientLike {
  connect(): Promise<void>;
  list(): Promise<ListEntry[]>;
  status(path: string, query: StatusQuery): Promise<MailboxStatus>;
  mailboxOpen(
    path: string,
    opts: { readOnly: boolean },
  ): Promise<MailboxOpenResult>;
  fetch(
    range: string,
    query: FetchQuery,
    opts?: { uid?: boolean },
  ): AsyncIterable<FetchMessage>;
  mailboxClose(): Promise<void>;
  /**
   * Acquire a read-write mailbox lock (imapflow `getMailboxLock`). Used ONLY
   * on the mutate path; the returned lock is released with `release()`, which
   * never issues IMAP CLOSE (no implicit expunge). Opening read-write any
   * other way on this type is forbidden.
   */
  getMailboxLock(
    path: string,
    opts: { readOnly: boolean },
  ): Promise<MailboxLock>;
  logout(): Promise<void>;
  /** Fan-out flag ADD over an entire UID set in one STORE (+FLAGS) command. */
  messageFlagsAdd(
    uids: number[],
    flags: string[],
    opts: { uid: true },
  ): Promise<unknown>;
  /** Fan-out flag REMOVE over an entire UID set in one STORE (-FLAGS) command. */
  messageFlagsRemove(
    uids: number[],
    flags: string[],
    opts: { uid: true },
  ): Promise<unknown>;
  /** Fan-out MOVE over an entire UID set in one MOVE command. */
  messageMove(
    uids: number[],
    destination: string,
    opts: { uid: true },
  ): Promise<unknown>;
  /**
   * Create a mailbox (IMAP CREATE). imapflow's own CREATE handler already
   * treats the ALREADYEXISTS (RFC 5530) server response as success,
   * resolving with `created: false` instead of throwing -- so a
   * well-behaved client never throws for an already-existing mailbox.
   * {@link isAlreadyExistsError} is defense-in-depth for a client that does.
   */
  mailboxCreate(path: string): Promise<{ path: string; created: boolean }>;
}

/** Builds a connected-on-demand client for the given config. */
export type ClientFactory = (cfg: GlobalArgs) => ImapClientLike;

/**
 * Default client factory: a thin adapter over the real imapflow client.
 * imapflow is constructed with `logger: false` to keep the mailbox credential
 * out of any log surface. `secure: false` (opportunistic STARTTLS, not
 * fail-closed) is refused unless the operator explicitly sets
 * `allowInsecure: true`, so the credential is never sent over a possibly
 * cleartext link by accident.
 *
 * @param cfg Resolved connection + credential settings.
 * @returns A read-only client seam backed by imapflow.
 * @throws If `secure` is false without `allowInsecure`.
 */
export function defaultClientFactory(cfg: GlobalArgs): ImapClientLike {
  if (!cfg.secure && !cfg.allowInsecure) {
    throw new Error(
      "Refusing to connect with secure=false: implicit TLS (secure=true, " +
        "port 993) is required unless allowInsecure=true is set explicitly.",
    );
  }
  const client = new ImapFlow({
    host: cfg.host,
    port: cfg.port,
    secure: cfg.secure,
    auth: { user: cfg.user, pass: cfg.password },
    logger: false,
  });
  return {
    connect: () => client.connect(),
    list: () => client.list() as unknown as Promise<ListEntry[]>,
    status: (path, query) =>
      client.status(path, query) as unknown as Promise<MailboxStatus>,
    mailboxOpen: async (path, opts) => {
      const box = await client.mailboxOpen(path, opts) as unknown as {
        exists?: number;
        uidValidity?: bigint | number;
      };
      return {
        exists: typeof box.exists === "number" ? box.exists : undefined,
        uidValidity: box.uidValidity === undefined
          ? undefined
          : Number(box.uidValidity),
      };
    },
    fetch: (range, query, opts) =>
      client.fetch(
        range,
        query as Record<string, unknown>,
        opts,
      ) as unknown as AsyncIterable<FetchMessage>,
    mailboxClose: () => client.mailboxClose() as unknown as Promise<void>,
    getMailboxLock: async (path, opts) => {
      // getMailboxLock SELECTs (readOnly:false) and resolves { path, release }.
      // release() clears the lock WITHOUT issuing IMAP CLOSE -- the whole point
      // of using it here instead of mailboxClose() (no implicit expunge). The
      // live SELECT state is read off client.mailbox after the lock is granted.
      const lock = await (client as unknown as {
        getMailboxLock: (
          p: string,
          o: { readOnly: boolean },
        ) => Promise<{ release: () => void }>;
      }).getMailboxLock(path, opts);
      const mb = (client as unknown as {
        mailbox?: { exists?: number; uidValidity?: bigint | number };
      }).mailbox;
      return {
        release: () => lock.release(),
        exists: mb && typeof mb.exists === "number" ? mb.exists : undefined,
        uidValidity: mb && mb.uidValidity !== undefined
          ? Number(mb.uidValidity)
          : undefined,
      };
    },
    logout: () => client.logout(),
    messageFlagsAdd: (uids, flags, opts) =>
      client.messageFlagsAdd(
        uids,
        flags,
        opts as unknown as Record<string, unknown>,
      ) as unknown as Promise<unknown>,
    messageFlagsRemove: (uids, flags, opts) =>
      client.messageFlagsRemove(
        uids,
        flags,
        opts as unknown as Record<string, unknown>,
      ) as unknown as Promise<unknown>,
    messageMove: (uids, destination, opts) =>
      client.messageMove(
        uids,
        destination,
        opts as unknown as Record<string, unknown>,
      ) as unknown as Promise<unknown>,
    mailboxCreate: async (path) => {
      const info = await client.mailboxCreate(path) as unknown as {
        path?: string;
        created?: boolean;
      };
      return {
        path: typeof info.path === "string" ? info.path : path,
        created: info.created === true,
      };
    },
  };
}

// ---------------------------------------------------------------------------
// Pure helpers (exported for tests)
// ---------------------------------------------------------------------------

/** The fixed set of raw headers `sync` requests (lowercase). NO body. */
export const SYNC_HEADERS: string[] = [
  "references",
  "list-id",
  "list-unsubscribe",
  "list-post",
  "reply-to",
  "auto-submitted",
  "precedence",
];

/**
 * Encode a folder path into a collision-free resource instance slug. Every
 * character outside `[A-Za-z0-9_.-]` is percent-escaped as `%` plus its
 * fixed-width 4-hex UTF-16 code unit. Because `%` never appears literally in
 * the safe set and the width is fixed, the mapping is injective: distinct
 * folder paths (e.g. "Team/Alpha" vs "Team.Alpha") always produce distinct
 * slugs, so one folder's snapshot can never overwrite another's.
 *
 * @param folder The IMAP folder path.
 * @returns A filesystem-safe, collision-free slug.
 */
export function folderSlug(folder: string): string {
  return folder
    .split("")
    .map((ch) =>
      /[A-Za-z0-9_.-]/.test(ch)
        ? ch
        : "%" + ch.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")
    )
    .join("");
}

/**
 * Coerce an imapflow flags value (Set or array) to a plain string array.
 *
 * @param v Flags as a Set, array, or absent.
 * @returns A string array (empty when absent).
 */
export function flagsToArray(v: Set<string> | string[] | undefined): string[] {
  if (!v) return [];
  return Array.isArray(v) ? [...v] : [...v.values()];
}

/**
 * Normalize an imapflow address list to {@link AddressSchema} rows.
 *
 * @param list Raw address array from an envelope, or undefined.
 * @returns Normalized `{ name, address }` rows.
 */
export function normalizeAddresses(
  list: Array<{ name?: string; address?: string }> | undefined,
): Array<{ name: string | null; address: string | null }> {
  if (!Array.isArray(list)) return [];
  return list.map((a) => ({
    name: a.name ?? null,
    address: a.address ?? null,
  }));
}

/**
 * Parse a raw RFC 5322 header block into a lowercase-keyed map, unfolding
 * continuation lines (those beginning with a space or tab). A blank line
 * terminates the header section (defensive: this model never fetches a body,
 * but a blank line still ends parsing so nothing past it is misread as a
 * header). When a header repeats, the first occurrence wins; repeats are
 * dropped (a Phase-1 simplification -- the captured headers are expected to be
 * singletons).
 *
 * @param raw The raw header bytes/string returned by a headers-only fetch.
 * @returns Map of lowercase header name to its unfolded value.
 */
export function parseHeaderBlock(
  raw: Uint8Array | string | undefined,
): Record<string, string> {
  if (raw === undefined) return {};
  const text = typeof raw === "string" ? raw : new TextDecoder().decode(raw);
  const out: Record<string, string> = {};
  const lines = text.split(/\r?\n/);
  const unfolded: string[] = [];
  for (const line of lines) {
    // A blank line ends the header section; ignore anything after it.
    if (line === "") break;
    if (/^[ \t]/.test(line) && unfolded.length > 0) {
      unfolded[unfolded.length - 1] += " " + line.trim();
    } else {
      unfolded.push(line);
    }
  }
  for (const line of unfolded) {
    const idx = line.indexOf(":");
    if (idx <= 0) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    if (!(key in out)) out[key] = value;
  }
  return out;
}

/**
 * Convert one fetched message (envelope + headers only) into a normalized
 * {@link Message}. No body is read.
 *
 * @param msg The raw fetch result.
 * @param folder The folder the message was fetched from.
 * @returns A normalized, header-only message record.
 */
export function normalizeMessage(msg: FetchMessage, folder: string): Message {
  const env = msg.envelope ?? {};
  const headers = parseHeaderBlock(msg.headers);
  const date = env.date === undefined
    ? null
    : (env.date instanceof Date ? env.date.toISOString() : String(env.date));
  return {
    uid: typeof msg.uid === "number" ? msg.uid : null,
    folder,
    from: normalizeAddresses(env.from),
    to: normalizeAddresses(env.to),
    cc: normalizeAddresses(env.cc),
    subject: env.subject ?? null,
    date,
    messageId: env.messageId ?? null,
    inReplyTo: env.inReplyTo ?? null,
    references: headers["references"] ?? null,
    listId: headers["list-id"] ?? null,
    listUnsubscribe: headers["list-unsubscribe"] ?? null,
    listPost: headers["list-post"] ?? null,
    replyTo: headers["reply-to"] ?? null,
    autoSubmitted: headers["auto-submitted"] ?? null,
    precedence: headers["precedence"] ?? null,
    flags: flagsToArray(msg.flags),
    size: typeof msg.size === "number" ? msg.size : null,
  };
}

/**
 * Byte length of a raw source value. A `Uint8Array` is counted directly; a
 * string is UTF-8 encoded first so the count reflects on-the-wire bytes.
 */
export function sourceByteLength(source: Uint8Array | string): number {
  return typeof source === "string"
    ? new TextEncoder().encode(source).length
    : source.byteLength;
}

/**
 * Byte length of a decoded attachment's content, WITHOUT retaining the
 * content. Accepts the shapes postal-mime yields (`ArrayBuffer`,
 * `Uint8Array`, or string); returns 0 when content is absent.
 */
function attachmentContentSize(
  content: ArrayBuffer | Uint8Array | string | undefined,
): number {
  if (content === undefined) return 0;
  if (typeof content === "string") {
    return new TextEncoder().encode(content).length;
  }
  return content.byteLength;
}

/**
 * The default MIME decoder: a thin wrapper over postal-mime's static
 * `PostalMime.parse`. It maps each attachment's decoded `content` byte length
 * to {@link ParsedMime} `size` and then DROPS the content (metadata only).
 * Pure with respect to the model: no network, no mailbox state -- it only
 * decodes the bytes handed to it, which is why it is safe to inject as the
 * `_parse` seam and to execute directly in tests.
 *
 * @param source The raw RFC822 message source (string or bytes).
 * @returns The decoded text/html plus attachment metadata.
 */
export const defaultParser: MimeParser = async (source) => {
  const email = await PostalMime.parse(source) as {
    text?: string | null;
    html?: string | null;
    attachments?: Array<{
      filename?: string | null;
      mimeType?: string | null;
      contentId?: string | null;
      content?: ArrayBuffer | Uint8Array | string;
    }>;
  };
  const attachments = (email.attachments ?? []).map((a) => ({
    filename: a.filename ?? null,
    mimeType: a.mimeType ?? null,
    contentId: a.contentId ?? null,
    size: attachmentContentSize(a.content),
  }));
  return {
    text: email.text ?? null,
    html: email.html ?? null,
    attachments,
  };
};

/**
 * Extract http/https URLs from the decoded text and html, de-duplicated in
 * first-seen order (text scanned before html). This is a deliberate HEURISTIC
 * -- a permissive URL regex, not a parser -- aimed at surfacing unsubscribe/
 * footer/receipt links for triage; it may over- or under-capture at odd URL
 * boundaries (e.g. trailing punctuation) and does not validate the URLs.
 *
 * @param text The decoded text/plain part, or null/undefined.
 * @param html The decoded text/html part, or null/undefined.
 * @returns The de-duplicated list of matched URLs in first-seen order.
 */
export function extractLinks(
  text: string | null | undefined,
  html: string | null | undefined,
): string[] {
  const re = /https?:\/\/[^\s<>"'`)\]}]+/gi;
  const seen = new Set<string>();
  const out: string[] = [];
  for (const src of [text, html]) {
    if (!src) continue;
    for (const match of src.matchAll(re)) {
      const url = match[0];
      if (!seen.has(url)) {
        seen.add(url);
        out.push(url);
      }
    }
  }
  return out;
}

/**
 * Byte-accurate truncation of a string to at most `maxBytes` UTF-8 bytes. This
 * is NOT a UTF-16 `.slice(0,N)` on code units: it encodes to UTF-8, cuts at the
 * byte boundary, then backs off any trailing continuation bytes so a multibyte
 * code point is never split (which would otherwise decode to a U+FFFD
 * replacement character).
 *
 * @param s The string to cap.
 * @param maxBytes The maximum UTF-8 byte length to keep.
 * @returns The prefix of `s` whose UTF-8 encoding is at most `maxBytes` bytes.
 */
export function truncateUtf8ToBytes(s: string, maxBytes: number): string {
  const bytes = new TextEncoder().encode(s);
  if (bytes.length <= maxBytes) return s;
  let end = maxBytes;
  // 0b10xxxxxx (0x80..0xBF) is a UTF-8 continuation byte; if the byte AT the
  // cut is one, the code point starting before it is split -- walk back to its
  // lead byte and exclude the whole (incomplete) code point.
  while (end > 0 && (bytes[end] & 0xC0) === 0x80) end--;
  return new TextDecoder().decode(bytes.subarray(0, end));
}

/**
 * Witness recorded on a `messageBody` when a UID was requested in the source
 * fetch (so it was UNDER the size cap) yet the server returned no source --
 * most likely expunged or moved between the size fetch and the source fetch.
 * Distinguishes a genuinely empty body from a silently dropped one (NF-1).
 */
export const SOURCE_NOT_RETURNED =
  "source not returned by server (expunged between size and source fetch?)";

/**
 * Build one {@link MessageBody} record. Reuses {@link normalizeMessage} for the
 * header/envelope fields, then layers the decoded body on top, enforcing the
 * {@link MAX_BODY_BYTES} cap via the pre-fetch size gate:
 *
 *   - `source === undefined` has TWO distinct meanings, kept honest and
 *     separate: (a) OVER-CAP -- the server's RFC822.SIZE (`serverSize`)
 *     exceeded the cap, so the body was DELIBERATELY NOT pulled: the record is
 *     `truncated: true`, `error: null`, `sourceBytes = serverSize`, null body,
 *     empty attachments/links; `truncated` honestly means "body withheld for
 *     size" (never a false alarm from attachment bytes) and the oversized
 *     source is never buffered. (b) UNDER-CAP BUT NO SOURCE -- the UID WAS
 *     requested in the source fetch but the server returned no source
 *     (expunged/vanished between the size and source fetches): the record is
 *     `truncated: false` (not a size decision) with `error` set to
 *     {@link SOURCE_NOT_RETURNED} as a witness, so the null body is never
 *     silent (NF-1). The over-cap and under-cap-missing paths are deliberately
 *     distinguishable by (`truncated`,`error`).
 *   - `source` present (an under-cap or no-server-size UID): decode it. `links`
 *     are extracted from the FULL decoded parts before any truncation so a cap
 *     never hides a link. If the ACTUAL source byte length still exceeds the
 *     cap (the no-server-size fallback), `text`/`html` are each byte-truncated
 *     via {@link truncateUtf8ToBytes} (never a UTF-16 char slice) and
 *     `truncated` is set; `sourceBytes` is the actual length.
 *
 * May throw if `parse` throws on hostile/malformed MIME -- the caller isolates
 * that per message (records an `error`, continues the batch).
 *
 * @param msg The header fetch result (envelope + flags + size + headers).
 * @param folder The folder the message was fetched from.
 * @param source The raw source for this UID, or undefined if withheld/absent.
 * @param serverSize The server-reported RFC822.SIZE, or undefined if none.
 * @param parse The injected MIME decoder.
 * @returns A decoded, cap-enforced message-body record (`error: null`).
 */
export async function buildMessageBody(
  msg: FetchMessage,
  folder: string,
  source: Uint8Array | string | undefined,
  serverSize: number | undefined,
  parse: MimeParser,
): Promise<MessageBody> {
  const header = normalizeMessage(msg, folder);
  const retrievedAt = new Date().toISOString();
  if (source === undefined) {
    const overCap = serverSize !== undefined && serverSize > MAX_BODY_BYTES;
    // Two distinct null-source paths, kept honest (NF-1):
    //   (a) OVER-CAP: body deliberately withheld for size -> truncated=true,
    //       no error (an intentional, documented decision).
    //   (b) UNDER-CAP BUT NO SOURCE: the UID WAS requested in the source fetch
    //       but the server returned none (expunged/vanished between the size
    //       and source fetches) -> truncated=false with an error witness, so a
    //       null body with non-zero sourceBytes is never silent.
    return {
      ...header,
      text: null,
      html: null,
      attachments: [],
      links: [],
      truncated: overCap,
      sourceBytes: serverSize ?? 0,
      error: overCap ? null : SOURCE_NOT_RETURNED,
      retrievedAt,
    };
  }
  const sourceBytes = sourceByteLength(source);
  const parsed = await parse(source);
  const fullText = parsed.text ?? null;
  const fullHtml = parsed.html ?? null;
  const attachments = parsed.attachments.map((a) => ({
    filename: a.filename ?? null,
    contentType: a.mimeType ?? null,
    size: typeof a.size === "number" ? a.size : null,
    contentId: a.contentId ?? null,
  }));
  const links = extractLinks(fullText, fullHtml);
  let text = fullText;
  let html = fullHtml;
  let truncated = false;
  if (sourceBytes > MAX_BODY_BYTES) {
    // No-server-size fallback: truncate on REAL bytes, never UTF-16 chars.
    truncated = true;
    if (text !== null) text = truncateUtf8ToBytes(text, MAX_BODY_BYTES);
    if (html !== null) html = truncateUtf8ToBytes(html, MAX_BODY_BYTES);
  }
  return {
    ...header,
    text,
    html,
    attachments,
    links,
    truncated,
    sourceBytes,
    error: null,
    retrievedAt,
  };
}

/**
 * Characters forbidden anywhere in an IMAP flag/keyword atom:
 * whitespace/control characters, and the atom-specials `(` `)` `{` `%` `*`
 * `"` `\` `]` (RFC 3501 sec. 9, `atom-specials`). Any backslash is rejected --
 * these methods set CUSTOM keywords only, never the system-flag namespace.
 */
// deno-lint-ignore no-control-regex -- intentional: rejecting CTL bytes (\x00-\x1f, \x7f) is the point of this grammar check, not a mistake.
const FORBIDDEN_IN_ATOM = /[\s(){%*"\\\]\x00-\x1f\x7f]/;

/**
 * Validate one custom keyword string against the IMAP atom grammar before it
 * ever reaches the wire. Rejects, in order:
 *   - empty strings;
 *   - the entire system-flag namespace: ANY leading backslash (`\Deleted`,
 *     `\Seen`, `\Recent`, ...). These methods set custom keywords only
 *     (cat/, list/, vendor/, flag/...); setting `\Deleted` is out of P3 scope
 *     and -- chained with an implicit expunge -- could covertly delete mail;
 *   - non-ASCII code points (>=0x80): IMAP atom CHAR is 7-bit US-ASCII, so an
 *     8-bit byte would be server-dependently mangled;
 *   - control characters, whitespace, and atom-specials (`(){}%*"\]`).
 * imapflow still owns the actual wire encoding -- this is a defense-in-depth
 * input gate, not a replacement for it.
 *
 * @param keyword The raw keyword string supplied by a caller.
 * @throws If the keyword violates the grammar or is a system flag.
 */
export function validateKeyword(keyword: string): void {
  if (keyword.length === 0) {
    throw new Error("Keyword must not be empty");
  }
  if (keyword.startsWith("\\")) {
    throw new Error(
      `Invalid keyword "${keyword}": the system-flag namespace (any leading ` +
        'backslash, e.g. "\\Deleted", "\\Seen") is rejected -- these methods ' +
        "set custom keywords only (cat/, list/, vendor/, flag/...).",
    );
  }
  for (const ch of keyword) {
    if ((ch.codePointAt(0) ?? 0) >= 0x80) {
      throw new Error(
        `Invalid keyword "${keyword}": non-ASCII code point (IMAP atoms are ` +
          "7-bit US-ASCII).",
      );
    }
  }
  if (FORBIDDEN_IN_ATOM.test(keyword)) {
    throw new Error(
      `Invalid keyword "${keyword}": contains a character forbidden by the ` +
        'IMAP atom grammar (no "(){}%*" \\ ], whitespace, or control characters)',
    );
  }
}

/**
 * Characters forbidden anywhere in a createFolder mailbox path: control
 * characters (CTL, 0x00-0x1F and 0x7F). Unlike {@link validateKeyword},
 * folder names legitimately contain spaces, slashes, dots, and most
 * punctuation (whatever the server's hierarchy delimiter and naming rules
 * allow) -- only control bytes are rejected here, as defense-in-depth before
 * the path ever reaches the wire.
 */
// deno-lint-ignore no-control-regex -- intentional: rejecting CTL bytes (\x00-\x1f, \x7f) is the point of this grammar check, not a mistake.
const FOLDER_CONTROL_CHAR = /[\x00-\x1f\x7f]/;

/**
 * Validate one createFolder mailbox path before it ever reaches the wire:
 * rejects empty (or all-whitespace) paths, leading/trailing whitespace, and
 * any control character. Leading/trailing whitespace is rejected (CF-6)
 * because " INBOX" and "INBOX" are DISTINCT, non-idempotent mailbox paths on
 * the wire -- silently trimming could create the wrong mailbox, so the caller
 * must pass the exact intended path.
 *
 * @param path The raw folder path supplied by a caller.
 * @throws If the path is empty/whitespace-only, has leading/trailing
 *   whitespace, or contains a control character.
 */
export function validateFolderPath(path: string): void {
  if (path.trim().length === 0) {
    throw new Error("Folder path must not be empty");
  }
  if (path !== path.trim()) {
    throw new Error(
      `Invalid folder path "${path}": leading or trailing whitespace is ` +
        "rejected (it would create a distinct, probably-unintended mailbox)",
    );
  }
  if (FOLDER_CONTROL_CHAR.test(path)) {
    throw new Error(
      `Invalid folder path "${path}": contains a control character`,
    );
  }
}

/**
 * Maximum number of distinct folders a single createFolder call may fan out
 * over. A mailbox tree rarely has more than a handful of new folders per
 * reconcile; a request far past this is almost certainly a mistake. Mirrors
 * the {@link MAX_UIDS} discipline on the message write methods: oversized
 * requests are rejected with a batching hint rather than silently processed.
 */
export const MAX_FOLDERS = 100;

/**
 * Enforce the {@link MAX_FOLDERS} cap on a (de-duplicated) folder set.
 *
 * @param folders The de-duplicated folder set about to be processed.
 * @throws If the set exceeds {@link MAX_FOLDERS}.
 */
export function checkFolderCap(folders: string[]): void {
  if (folders.length > MAX_FOLDERS) {
    throw new Error(
      `Refusing to create ${folders.length} folders in one call: the cap ` +
        `is ${MAX_FOLDERS}. Batch the folder set into chunks of at most ` +
        `${MAX_FOLDERS} and call again per chunk.`,
    );
  }
}

/**
 * Detect whether a thrown error represents the IMAP ALREADYEXISTS response
 * code (RFC 5530) -- CREATE found the mailbox already present. imapflow's
 * own mailboxCreate already normalizes this into a non-throwing
 * `{ created: false }` result (its CREATE command handler catches the
 * ALREADYEXISTS response code itself), so a well-behaved client never
 * reaches this function for an already-existing mailbox. Checked as
 * defense-in-depth ONLY to decide whether to treat a thrown create call as
 * an idempotent no-op instead of a genuine failure -- never used to swallow
 * any OTHER error.
 *
 * @param err The error thrown by {@link ImapClientLike.mailboxCreate}.
 * @returns true if the error represents ALREADYEXISTS.
 */
export function isAlreadyExistsError(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  const code = (err as { serverResponseCode?: unknown }).serverResponseCode;
  if (typeof code === "string" && code.toUpperCase() === "ALREADYEXISTS") {
    return true;
  }
  return /ALREADYEXISTS/i.test(err.message);
}

/**
 * Maximum number of distinct UIDs a single write method call may fan out over.
 * One fan-out command carries every UID on one IMAP command line; an unbounded
 * set could exceed server line limits or stress the session. Oversized
 * requests are rejected with a batching hint rather than silently chunked, so
 * the single-command fan-out invariant holds for every in-cap call.
 */
export const MAX_UIDS = 1000;

/**
 * Enforce the {@link MAX_UIDS} cap on a (de-duplicated) UID set.
 *
 * @param uids The de-duplicated UID set about to be fanned out.
 * @throws If the set exceeds {@link MAX_UIDS}.
 */
export function checkUidCap(uids: number[]): void {
  if (uids.length > MAX_UIDS) {
    throw new Error(
      `Refusing to operate on ${uids.length} UIDs in one call: the cap is ` +
        `${MAX_UIDS} (single fan-out command). Batch the UID set into chunks ` +
        `of at most ${MAX_UIDS} and call again per chunk.`,
    );
  }
}

/**
 * Maximum number of distinct UIDs a single {@link fetchMessage} call may fan
 * out over -- far lower than {@link MAX_UIDS} (25, not 1000) because one call
 * pulls up to N FULL message sources and PERSISTS each as its own record. A
 * header-only `sync` is cheap per message; a full-body fetch is not. Oversized
 * requests are rejected with a batching hint, never silently chunked.
 */
export const MAX_FETCH_UIDS = 25;

/**
 * Per-message raw-source byte cap for {@link fetchMessage}. A message whose raw
 * source exceeds this degrades to a FLAGGED partial record (`truncated: true`,
 * `sourceBytes` recording the real size, `text`/`html` capped) rather than
 * blowing up the run or bloating the store with an unbounded body.
 */
export const MAX_BODY_BYTES = 1_000_000;

/**
 * Enforce the {@link MAX_FETCH_UIDS} cap on a (de-duplicated) UID set.
 *
 * @param uids The de-duplicated UID set about to be fetched.
 * @throws If the set exceeds {@link MAX_FETCH_UIDS}.
 */
export function checkFetchUidCap(uids: number[]): void {
  if (uids.length > MAX_FETCH_UIDS) {
    throw new Error(
      `Refusing to fetch ${uids.length} full message bodies in one call: the ` +
        `cap is ${MAX_FETCH_UIDS} (each UID pulls a full source and is ` +
        `persisted). Batch the UID set into chunks of at most ` +
        `${MAX_FETCH_UIDS} and call again per chunk.`,
    );
  }
}

/**
 * Guard against mutating a stale UID selection. No-op when `requested` is
 * undefined (the guard was not asked for). Fails CLOSED when `requested` is
 * given but the server did not report a live UIDVALIDITY to check it
 * against -- an unverifiable guard is treated as a mismatch, not as a pass.
 *
 * @param live The mailbox's live UIDVALIDITY, if the server reported one.
 * @param requested The caller-supplied UIDVALIDITY to verify, if any.
 * @param folder The folder being guarded (for the error message).
 * @throws If `requested` is given and does not match (or cannot be verified
 *   against) `live`.
 */
export function checkUidValidity(
  live: number | undefined,
  requested: number | undefined,
  folder: string,
): void {
  if (requested === undefined) return;
  if (live === undefined) {
    throw new Error(
      `Refusing to mutate ${folder}: uidValidity=${requested} was requested ` +
        "but the server did not report a live UIDVALIDITY to verify it " +
        "against.",
    );
  }
  if (live !== requested) {
    throw new Error(
      `Refusing to mutate ${folder}: stale selection (requested ` +
        `uidValidity=${requested}, live uidValidity=${live}). Re-select UIDs ` +
        "from a fresh sync before mutating.",
    );
  }
}

/** De-duplicate a UID list, preserving first-seen order. */
function dedupeUids(uids: number[]): number[] {
  return [...new Set(uids)];
}

/**
 * De-duplicate a keyword list, preserving first-seen order. An IMAP flag set
 * cannot hold a duplicate token, so recording one in the evidence would be a
 * data-quality bug (CORR-7).
 */
function dedupeKeywords(keywords: string[]): string[] {
  return [...new Set(keywords)];
}

/**
 * Fetch the live folder list and reduce it to the set of existing paths plus
 * the server's hierarchy delimiter (the first non-empty delimiter seen
 * across entries; null if the server reported none). Shared by
 * createFolder's preview, apply, and post-creation verification phases --
 * never re-implemented per call site. createFolder is a mailbox-level op, so
 * this (not mailboxOpen/EXAMINE) is its entire "inspect" phase.
 */
async function listFolderPaths(
  client: ImapClientLike,
): Promise<{ existingPaths: Set<string>; delimiter: string | null }> {
  const entries = await client.list();
  const existingPaths = new Set(entries.map((e) => e.path));
  let delimiter: string | null = null;
  for (const e of entries) {
    if (e.delimiter) {
      delimiter = String(e.delimiter);
      break;
    }
  }
  return { existingPaths, delimiter };
}

// ---------------------------------------------------------------------------
// Shared write-core helpers.
//
// addKeywords, removeKeywords, move, and applyTagPlan all share the SAME
// two-phase safety core: EXAMINE (read-only) to inspect, diff against the
// requested change, then -- ONLY if something will change and dryRun=false --
// a read-write LOCK (never CLOSE) to mutate, followed by a post-mutation
// re-FETCH to verify. These helpers factor that core out so every call site
// gets the identical open/close discipline, uidValidity guard, and
// verification instead of a re-implemented copy.
// ---------------------------------------------------------------------------

/** Fetch current flags for a UID set under the currently open/selected mailbox. */
async function fetchFlagsByUid(
  client: ImapClientLike,
  uids: number[],
): Promise<Map<number, string[]>> {
  const out = new Map<number, string[]>();
  for await (
    const msg of client.fetch(
      uids.join(","),
      { uid: true, flags: true },
      { uid: true },
    )
  ) {
    if (typeof msg.uid === "number") out.set(msg.uid, flagsToArray(msg.flags));
  }
  return out;
}

/** Determine which of a UID set are present under the currently open mailbox. */
async function fetchPresentUids(
  client: ImapClientLike,
  uids: number[],
): Promise<Set<number>> {
  const out = new Set<number>();
  for await (
    const msg of client.fetch(uids.join(","), { uid: true }, { uid: true })
  ) {
    if (typeof msg.uid === "number") out.add(msg.uid);
  }
  return out;
}

/**
 * PHASE 1 (keyword ops) -- open `folder` under EXAMINE (read-only), guard
 * `uidValidity`, and fetch the current flags for `uids` (skipped when `uids`
 * is empty, so no empty-range FETCH is ever sent). Always closes the mailbox
 * (CLOSE-safe: EXAMINE never expunges) before returning or throwing.
 */
async function inspectKeywordState(
  client: ImapClientLike,
  folder: string,
  uids: number[],
  requestedUidValidity: number | undefined,
): Promise<{ uidValidityOut: number | null; current: Map<number, string[]> }> {
  const box = await client.mailboxOpen(folder, { readOnly: true });
  try {
    checkUidValidity(box.uidValidity, requestedUidValidity, folder);
    const uidValidityOut = box.uidValidity ?? null;
    const current = uids.length === 0
      ? new Map<number, string[]>()
      : await fetchFlagsByUid(client, uids);
    return { uidValidityOut, current };
  } finally {
    await client.mailboxClose();
  }
}

/**
 * PHASE 1 (move) -- open `folder` under EXAMINE, guard `uidValidity`, and
 * determine which of `uids` are present in the source. Always closes.
 */
async function inspectPresence(
  client: ImapClientLike,
  folder: string,
  uids: number[],
  requestedUidValidity: number | undefined,
): Promise<{ uidValidityOut: number | null; present: Set<number> }> {
  const box = await client.mailboxOpen(folder, { readOnly: true });
  try {
    checkUidValidity(box.uidValidity, requestedUidValidity, folder);
    const uidValidityOut = box.uidValidity ?? null;
    const present = uids.length === 0
      ? new Set<number>()
      : await fetchPresentUids(client, uids);
    return { uidValidityOut, present };
  } finally {
    await client.mailboxClose();
  }
}

/** One keyword-add diff row + the bookkeeping addKeywords/applyTagPlan need. */
interface KeywordDiff {
  items: Array<
    { uid: number; folder: string; before: string[]; after: string[] }
  >;
  skipped: Array<{ uid: number; reason: string }>;
  changedUids: number[];
}

/**
 * Pure diff: which of `uids` would gain at least one of `keywords`, which
 * already have them all (skipped), and which are absent from the folder
 * entirely (also skipped). Shared by addKeywords and applyTagPlan's
 * per-(folder,keyword) group (called there with a single-element array).
 */
function diffAddKeywords(
  folder: string,
  current: Map<number, string[]>,
  uids: number[],
  keywords: string[],
): KeywordDiff {
  const items: KeywordDiff["items"] = [];
  const skipped: KeywordDiff["skipped"] = [];
  const changedUids: number[] = [];
  for (const uid of uids) {
    const cur = current.get(uid);
    if (cur === undefined) {
      skipped.push({ uid, reason: "uid not found in folder" });
      continue;
    }
    const missing = keywords.filter((k) => !cur.includes(k));
    const after = missing.length > 0 ? [...cur, ...missing] : cur;
    items.push({ uid, folder, before: cur, after });
    if (missing.length > 0) changedUids.push(uid);
    else skipped.push({ uid, reason: "keyword(s) already present" });
  }
  return { items, skipped, changedUids };
}

/**
 * Pure diff: which of `uids` would lose at least one of `keywords`, which
 * already lack them all (skipped), and which are absent from the folder
 * entirely (also skipped). Shared by removeKeywords only (applyTagPlan is
 * add-only per its build spec).
 */
function diffRemoveKeywords(
  folder: string,
  current: Map<number, string[]>,
  uids: number[],
  keywords: string[],
): KeywordDiff {
  const items: KeywordDiff["items"] = [];
  const skipped: KeywordDiff["skipped"] = [];
  const changedUids: number[] = [];
  for (const uid of uids) {
    const cur = current.get(uid);
    if (cur === undefined) {
      skipped.push({ uid, reason: "uid not found in folder" });
      continue;
    }
    const present = keywords.filter((k) => cur.includes(k));
    const after = present.length > 0
      ? cur.filter((f) => !keywords.includes(f))
      : cur;
    items.push({ uid, folder, before: cur, after });
    if (present.length > 0) changedUids.push(uid);
    else skipped.push({ uid, reason: "keyword(s) already absent" });
  }
  return { items, skipped, changedUids };
}

/**
 * PHASE 2 drift guard: the mailbox's UIDVALIDITY must not have changed
 * between the Phase-1 EXAMINE and the Phase-2 read-write LOCK (a renumbering
 * between inspect and mutate -- NEW-1). No-op when either side is unknown.
 */
function assertNoUidValidityDrift(
  uidValidityOut: number | null,
  liveUidValidity: number | undefined,
  folder: string,
): void {
  if (
    liveUidValidity !== undefined && uidValidityOut !== null &&
    liveUidValidity !== uidValidityOut
  ) {
    throw new Error(
      `Refusing to mutate ${folder}: UIDVALIDITY changed between inspect ` +
        `(${uidValidityOut}) and mutate (${liveUidValidity}).`,
    );
  }
}

/** One discrepancy row (matches {@link DiscrepancyItemSchema}). */
interface DiscrepancyRow {
  uid: number;
  reason: string;
  expected?: string[];
  actual?: string[];
}

/**
 * CORR-3 verification, shared by addKeywords/removeKeywords/applyTagPlan's
 * keyword groups: re-FETCH `changedUids` under the still-held read-write
 * lock, record the ACTUAL resulting flags into `items` (mutated in place --
 * reality, not the prediction), and return any UID whose post-mutation state
 * did not reach what was expected.
 */
async function verifyKeywordMutation(
  client: ImapClientLike,
  changedUids: number[],
  keywords: string[],
  items: KeywordDiff["items"],
  mode: "add" | "remove",
): Promise<DiscrepancyRow[]> {
  const actual = await fetchFlagsByUid(client, changedUids);
  const discrepancies: DiscrepancyRow[] = [];
  const changedSet = new Set(changedUids);
  for (const it of items) {
    if (!changedSet.has(it.uid)) continue;
    const got = actual.get(it.uid);
    const expected = it.after;
    if (got === undefined) {
      discrepancies.push({
        uid: it.uid,
        reason: "uid absent on post-mutation re-fetch (expunged or moved?)",
        expected,
      });
      continue;
    }
    it.after = got; // record reality, not the prediction
    if (mode === "add") {
      const unmet = keywords.filter((k) => !got.includes(k));
      if (unmet.length > 0) {
        discrepancies.push({
          uid: it.uid,
          reason: `keyword(s) not present after add: ${unmet.join(", ")}`,
          expected,
          actual: got,
        });
      }
    } else {
      const stillPresent = keywords.filter((k) => got.includes(k));
      if (stillPresent.length > 0) {
        discrepancies.push({
          uid: it.uid,
          reason: `keyword(s) still present after remove: ${
            stillPresent.join(", ")
          }`,
          expected,
          actual: got,
        });
      }
    }
  }
  return discrepancies;
}

/**
 * Pure diff (move): which of `uids` are present in the source (would move)
 * vs. absent (CORR-1 `missingFromSource` -- an anomaly, never conflated with
 * success). Shared by move and applyTagPlan's per-(folder,destination) group.
 */
function diffMove(
  folder: string,
  destination: string,
  present: Set<number>,
  uids: number[],
): {
  items: Array<{ uid: number; from: string; to: string }>;
  missingFromSource: Array<{ uid: number; reason: string }>;
  moveUids: number[];
} {
  const items: Array<{ uid: number; from: string; to: string }> = [];
  const missingFromSource: Array<{ uid: number; reason: string }> = [];
  const moveUids: number[] = [];
  for (const uid of uids) {
    if (!present.has(uid)) {
      missingFromSource.push({
        uid,
        reason: "not present in source folder -- expunged or moved " +
          "elsewhere; NOT confirmed in destination",
      });
      continue;
    }
    items.push({ uid, from: folder, to: destination });
    moveUids.push(uid);
  }
  return { items, missingFromSource, moveUids };
}

/**
 * CORR-3 verification (move): re-check source presence for `moveUids` under
 * the still-held read-write lock; any UID STILL present did not move.
 */
async function verifyMoveMutation(
  client: ImapClientLike,
  moveUids: number[],
): Promise<Array<{ uid: number; reason: string }>> {
  const stillPresent = await fetchPresentUids(client, moveUids);
  const discrepancies: Array<{ uid: number; reason: string }> = [];
  for (const uid of moveUids) {
    if (stillPresent.has(uid)) {
      discrepancies.push({
        uid,
        reason: "still present in source after move (server did not move it)",
      });
    }
  }
  return discrepancies;
}

/** Build a `wouldAffect` (dryRun=true preview) record. */
function wouldAffectRecord(p: {
  op: "addKeywords" | "removeKeywords" | "move";
  folder: string;
  destination?: string;
  uidValidity: number | null;
  requestedCount: number;
  resolvedCount: number;
  count: number;
  items: unknown[];
  skipped: Array<{ uid: number; reason: string }>;
  missingFromSource: Array<{ uid: number; reason: string }>;
}): Record<string, unknown> {
  return {
    op: p.op,
    folder: p.folder,
    ...(p.destination !== undefined ? { destination: p.destination } : {}),
    uidValidity: p.uidValidity,
    dryRun: true,
    requestedCount: p.requestedCount,
    resolvedCount: p.resolvedCount,
    count: p.count,
    items: p.items,
    skipped: p.skipped,
    missingFromSource: p.missingFromSource,
    retrievedAt: new Date().toISOString(),
  };
}

/** Build an `applied` (dryRun=false result) record. */
function appliedRecord(p: {
  op: "addKeywords" | "removeKeywords" | "move";
  folder: string;
  destination?: string;
  uidValidity: number | null;
  requestedCount: number;
  resolvedCount: number;
  applied: number;
  items: unknown[];
  skipped: Array<{ uid: number; reason: string }>;
  missingFromSource: Array<{ uid: number; reason: string }>;
  discrepancies: unknown[];
  serverResponses: unknown[];
  error?: string;
}): Record<string, unknown> {
  return {
    op: p.op,
    folder: p.folder,
    ...(p.destination !== undefined ? { destination: p.destination } : {}),
    uidValidity: p.uidValidity,
    requestedCount: p.requestedCount,
    resolvedCount: p.resolvedCount,
    applied: p.applied,
    skipped: p.skipped,
    missingFromSource: p.missingFromSource,
    items: p.items,
    discrepancies: p.discrepancies,
    serverResponses: p.serverResponses,
    ...(p.error !== undefined ? { error: p.error } : {}),
    retrievedAt: new Date().toISOString(),
  };
}

/** Build a createFolder `wouldAffect`-shaped preview (dryRun=true) record. */
function createFolderPreviewRecord(p: {
  delimiter: string | null;
  items: Array<
    { folder: string; existsAlready: boolean; wouldCreate: boolean }
  >;
}): Record<string, unknown> {
  const existingCount = p.items.filter((i) => i.existsAlready).length;
  return {
    dryRun: true,
    delimiter: p.delimiter,
    requestedCount: p.items.length,
    existingCount,
    wouldCreateCount: p.items.length - existingCount,
    items: p.items,
    retrievedAt: new Date().toISOString(),
  };
}

/** One createFolder dryRun=false per-folder result row. */
interface CreateFolderResultItem {
  folder: string;
  canonicalPath: string;
  existedBefore: boolean;
  created: boolean;
  alreadyExisted: boolean;
  verifiedExists: boolean;
}

/** Build a createFolder `applied`-shaped result (dryRun=false) record. */
function createFolderResultRecord(p: {
  delimiter: string | null;
  requestedCount: number;
  items: CreateFolderResultItem[];
  discrepancies: Array<{ folder: string; reason: string }>;
  serverResponses: unknown[];
  error?: string;
}): Record<string, unknown> {
  return {
    dryRun: false,
    delimiter: p.delimiter,
    requestedCount: p.requestedCount,
    // CF-5: count only VERIFIED creations -- a folder the server claimed to
    // create but the re-LIST could not confirm is a discrepancy, not a
    // success, and must not inflate createdCount.
    createdCount: p.items.filter((i) => i.created && i.verifiedExists).length,
    alreadyExistedCount: p.items.filter((i) => i.alreadyExisted).length,
    items: p.items,
    discrepancies: p.discrepancies,
    serverResponses: p.serverResponses,
    ...(p.error !== undefined ? { error: p.error } : {}),
    retrievedAt: new Date().toISOString(),
  };
}

/** Split a UID list into chunks of at most {@link MAX_UIDS}, in order. */
function chunkUids(uids: number[]): number[][] {
  const out: number[][] = [];
  for (let i = 0; i < uids.length; i += MAX_UIDS) {
    out.push(uids.slice(i, i + MAX_UIDS));
  }
  return out;
}

/** One (folder,keyword) group's aggregated result (across all its chunks). */
interface KeywordGroupResult {
  preview?: {
    folder: string;
    keyword: string;
    uidValidity: number | null;
    uidValidityDiverged: boolean;
    uidCount: number;
    addCount: number;
    alreadyPresentCount: number;
    notFound: number;
  };
  applied?: {
    folder: string;
    keyword: string;
    uidValidity: number | null;
    uidValidityDiverged: boolean;
    uidCount: number;
    appliedCount: number;
    alreadyPresentCount: number;
    notFound: number;
    discrepancies: DiscrepancyRow[];
  };
}

/**
 * Track a group's UIDVALIDITY across chunks (ATP-5): keep the first non-null
 * value as canonical and flag when a later chunk reports a DIFFERENT non-null
 * value (a mid-group renumbering the single consolidated row would otherwise
 * mask). Per-chunk {@link assertNoUidValidityDrift} still protects
 * correctness within a chunk; this only governs faithful REPORTING.
 */
class UidValidityTracker {
  value: number | null = null;
  diverged = false;
  observe(v: number | null): void {
    if (v === null) return;
    if (this.value === null) this.value = v;
    else if (this.value !== v) this.diverged = true;
  }
}

/**
 * Run applyTagPlan's per-(folder,keyword) group through the SAME safety core
 * as addKeywords: chunked into at most {@link MAX_UIDS} UIDs per fan-out
 * STORE (a group over the cap is split into multiple calls -- never
 * rejected, unlike the direct addKeywords method). `uids` must already be
 * de-duplicated by the caller.
 */
async function processKeywordGroup(
  client: ImapClientLike,
  folder: string,
  keyword: string,
  uids: number[],
  dryRun: boolean,
): Promise<KeywordGroupResult> {
  const uidValidity = new UidValidityTracker();
  let uidCount = 0;
  let addCount = 0;
  let alreadyPresentCount = 0;
  let notFound = 0;
  let appliedCount = 0;
  const discrepancies: DiscrepancyRow[] = [];

  for (const part of chunkUids(uids)) {
    const inspected = await inspectKeywordState(
      client,
      folder,
      part,
      undefined,
    );
    uidValidity.observe(inspected.uidValidityOut);
    uidCount += part.length;
    const { items, changedUids } = diffAddKeywords(
      folder,
      inspected.current,
      part,
      [keyword],
    );
    // `items` has a row for every UID FOUND in the folder (whether it changed
    // or was already present); UIDs the diff dropped as not-found are the
    // gap. ATP-1: surface that gap as `notFound` (the keyword analogue of a
    // move group's missingFromSource) instead of silently absorbing it.
    alreadyPresentCount += items.length - changedUids.length;
    notFound += part.length - items.length;

    if (dryRun) {
      addCount += changedUids.length;
      continue;
    }
    if (changedUids.length === 0) continue;

    const lock = await client.getMailboxLock(folder, { readOnly: false });
    try {
      assertNoUidValidityDrift(uidValidity.value, lock.uidValidity, folder);
      await client.messageFlagsAdd(changedUids, [keyword], { uid: true });
      const chunkDiscrepancies = await verifyKeywordMutation(
        client,
        changedUids,
        [keyword],
        items,
        "add",
      );
      discrepancies.push(...chunkDiscrepancies);
      appliedCount += changedUids.length - chunkDiscrepancies.length;
    } finally {
      lock.release();
    }
  }

  return dryRun
    ? {
      preview: {
        folder,
        keyword,
        uidValidity: uidValidity.value,
        uidValidityDiverged: uidValidity.diverged,
        uidCount,
        addCount,
        alreadyPresentCount,
        notFound,
      },
    }
    : {
      applied: {
        folder,
        keyword,
        uidValidity: uidValidity.value,
        uidValidityDiverged: uidValidity.diverged,
        uidCount,
        appliedCount,
        alreadyPresentCount,
        notFound,
        discrepancies,
      },
    };
}

/** One (folder,destination) group's aggregated result (across all its chunks). */
interface MoveGroupResult {
  preview?: {
    folder: string;
    destination: string;
    uidValidity: number | null;
    uidValidityDiverged: boolean;
    uidCount: number;
    missingFromSource: number;
  };
  applied?: {
    folder: string;
    destination: string;
    uidValidity: number | null;
    uidValidityDiverged: boolean;
    uidCount: number;
    appliedCount: number;
    missingFromSource: number;
    discrepancies: Array<{ uid: number; reason: string }>;
  };
}

/**
 * Run applyTagPlan's per-(folder,destination) group through the SAME safety
 * core as move: chunked into at most {@link MAX_UIDS} UIDs per fan-out MOVE.
 * `uids` must already be de-duplicated by the caller.
 */
async function processMoveGroup(
  client: ImapClientLike,
  folder: string,
  destination: string,
  uids: number[],
  dryRun: boolean,
): Promise<MoveGroupResult> {
  const uidValidity = new UidValidityTracker();
  let uidCount = 0;
  let missingFromSourceCount = 0;
  let appliedCount = 0;
  const discrepancies: Array<{ uid: number; reason: string }> = [];

  for (const part of chunkUids(uids)) {
    const inspected = await inspectPresence(client, folder, part, undefined);
    uidValidity.observe(inspected.uidValidityOut);
    uidCount += part.length;
    const { missingFromSource, moveUids } = diffMove(
      folder,
      destination,
      inspected.present,
      part,
    );
    missingFromSourceCount += missingFromSource.length;

    if (dryRun || moveUids.length === 0) continue;

    const lock = await client.getMailboxLock(folder, { readOnly: false });
    try {
      assertNoUidValidityDrift(uidValidity.value, lock.uidValidity, folder);
      await client.messageMove(moveUids, destination, { uid: true });
      const chunkDiscrepancies = await verifyMoveMutation(client, moveUids);
      discrepancies.push(...chunkDiscrepancies);
      appliedCount += moveUids.length - chunkDiscrepancies.length;
    } finally {
      lock.release();
    }
  }

  return dryRun
    ? {
      preview: {
        folder,
        destination,
        uidValidity: uidValidity.value,
        uidValidityDiverged: uidValidity.diverged,
        uidCount,
        missingFromSource: missingFromSourceCount,
      },
    }
    : {
      applied: {
        folder,
        destination,
        uidValidity: uidValidity.value,
        uidValidityDiverged: uidValidity.diverged,
        uidCount,
        appliedCount,
        missingFromSource: missingFromSourceCount,
        discrepancies,
      },
    };
}

// ---------------------------------------------------------------------------
// Context + method helpers
// ---------------------------------------------------------------------------

/** Minimal logging surface the methods rely on. */
interface MethodLogger {
  info(message: string, properties?: Record<string, unknown>): void;
  warning(message: string, properties?: Record<string, unknown>): void;
}

/** Minimal shape of the execute context this model relies on. */
interface ExecuteContext {
  globalArgs: GlobalArgs;
  logger: MethodLogger;
  /**
   * Cross-model read (repo rule 3): used ONLY by applyTagPlan to read the
   * latest `tagPlan` record from a named `@shrug/mail-ontology` instance. It
   * is never used to recompute classification -- applyTagPlan reads the
   * already-decided plan, nothing more.
   */
  readModelData: (
    modelName: string,
    specName?: string,
  ) => Promise<DataRecord[]>;
  writeResource: (
    specName: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<{ name: string }>;
}

/** A cross-model data record as returned by `readModelData`. */
export interface DataRecord {
  name: string;
  specName?: string;
  attributes?: Record<string, unknown>;
}

/** One decoded tagPlan item. */
export type TagPlanItem = z.infer<typeof TagPlanItemSchema>;

/**
 * Never-throw coercion of the latest cross-model `tagPlan` record into a
 * {@link TagPlanItemSchema} list. Structurally malformed entries (not an
 * object, missing/empty folder, non-numeric uid) are DROPPED -- defensive
 * decoding of an untyped cross-model boundary, distinct from the
 * keyword-validity gate applyTagPlan runs afterward (which ABORTS rather than
 * drops). ATP-2: the count of dropped entries is returned so applyTagPlan can
 * surface it as `droppedCount`, making decode drift against
 * @shrug/mail-ontology visible instead of silent. Exported for unit testing.
 *
 * @param rec The latest `tagPlan` data record, or undefined if none exists.
 * @returns `{ items, droppedCount }` (both zero/empty when `rec` is absent).
 */
export function toTagPlanItems(
  rec: DataRecord | undefined,
): { items: TagPlanItem[]; droppedCount: number } {
  const raw = rec?.attributes?.items;
  if (!Array.isArray(raw)) return { items: [], droppedCount: 0 };
  const items: TagPlanItem[] = [];
  let droppedCount = 0;
  for (const entry of raw) {
    if (typeof entry !== "object" || entry === null) {
      droppedCount++;
      continue;
    }
    const r = entry as Record<string, unknown>;
    if (typeof r.folder !== "string" || r.folder.length === 0) {
      droppedCount++;
      continue;
    }
    if (typeof r.uid !== "number") {
      droppedCount++;
      continue;
    }
    const keywords = Array.isArray(r.keywords)
      ? r.keywords.filter((k): k is string => typeof k === "string")
      : [];
    const financeMove = typeof r.financeMove === "string"
      ? r.financeMove
      : null;
    items.push({ folder: r.folder, uid: r.uid, keywords, financeMove });
  }
  return { items, droppedCount };
}

/** Return shape for every method's execute function. */
interface ExecuteResult {
  dataHandles: Array<{ name: string }>;
}

/**
 * Normalize a `folder` argument (string, array, or absent) to a de-duplicated
 * string list, preserving first-seen order.
 */
function foldersArg(
  folder: string | string[] | undefined,
  fallback: string,
): string[] {
  const raw = folder === undefined
    ? [fallback]
    : (Array.isArray(folder) ? folder : [folder]);
  return [...new Set(raw)];
}

// ---------------------------------------------------------------------------
// Model definition
// ---------------------------------------------------------------------------

/** Provider-agnostic IMAP inspection (read-only) + gated write model. */
export const model = {
  type: "@shrug/imap",
  version: "2026.10.14.1",
  description:
    "Provider-agnostic IMAP over imapflow: read-only listFolders/sync " +
    "(EXAMINE; folder tree + header/envelope-only snapshots, no bodies) and " +
    "read-only fetchMessage (EXAMINE; ONE folder per call; decodes FULL " +
    "message bodies by UID via postal-mime into per-UID messageBody records " +
    "-- text/html + attachment metadata + extracted links + an error field). " +
    "A pre-fetch size gate (one {uid,size} fetch then one source fetch for " +
    "under-cap UIDs) withholds over-cap bodies (truncated=true, never " +
    "buffered); each decode is isolated so one bad message cannot abort the " +
    "batch; records have a FINITE lifetime. html is stored UNSANITIZED. Plus " +
    "gated write methods addKeywords/removeKeywords/move/applyTagPlan/" +
    "createFolder. dryRun defaults true and is the only non-mutating path; " +
    "previews open EXAMINE (read-only), mutations open read-write via " +
    "getMailboxLock and release WITHOUT IMAP CLOSE (never an implicit " +
    "expunge); uidValidity-guarded; custom keywords only (system-flag " +
    "namespace rejected); UID set capped (applyTagPlan chunks instead of " +
    "rejecting); single fan-out operation per call/group; applied evidence " +
    "is verified by a post-mutation re-FETCH. applyTagPlan consumes a " +
    "@shrug/mail-ontology tagPlan record and fans it out over the SAME " +
    "safety core. createFolder ensures a list of mailbox paths exist in ONE " +
    "call (IMAP CREATE), idempotent on ALREADYEXISTS, verified by a " +
    "post-creation re-LIST; it is mailbox-level and needs no UID/" +
    "uidValidity machinery. copy/expunge/delete remain out of scope.",
  globalArguments: GlobalArgsSchema,
  resources: {
    "folders": {
      description: "The folder tree with per-folder message counts and sizes",
      schema: FolderTreeSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "snapshot": {
      description:
        "A header/envelope-only snapshot of one folder's messages (no bodies)",
      schema: SnapshotSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "messageBody": {
      description:
        "One message's decoded FULL body by UID (fetchMessage): text/html, " +
        "attachment metadata, extracted links, truncation witnesses. FINITE " +
        "lifetime (30d) so third-party body content does not persist forever.",
      schema: MessageBodySchema,
      // Bounded TTL (not "infinite"): full third-party body content is
      // sensitive and should age out. 30 days is a sensible triage window.
      lifetime: "30d",
      garbageCollection: 20,
    },
    "wouldAffect": {
      description:
        "A dryRun=true preview of a write method's effect; NO mutation performed",
      schema: WouldAffectSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "applied": {
      description: "The result of a write method executed with dryRun=false",
      schema: AppliedSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "tagPlanPreview": {
      description:
        "A consolidated dryRun=true preview of applying a @shrug/mail-ontology " +
        "tagPlan (applyTagPlan); NO mutation performed",
      schema: TagPlanPreviewSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "tagPlanApplied": {
      description:
        "The consolidated result of applying a @shrug/mail-ontology tagPlan " +
        "(applyTagPlan) with dryRun=false",
      schema: TagPlanAppliedSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "createFolderPreview": {
      description:
        "A dryRun=true preview of createFolder; NO mutation performed",
      schema: CreateFolderPreviewSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "createFolderResult": {
      description: "The result of createFolder executed with dryRun=false",
      schema: CreateFolderResultSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
  },
  methods: {
    listFolders: {
      description:
        "Enumerate the folder tree and attach each folder's message count and " +
        "total size (IMAP LIST + STATUS). Read-only; no mailbox is modified.",
      arguments: z.object({}),
      execute: async (
        args: { _client?: ClientFactory },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const client = (args._client ?? defaultClientFactory)(cfg);
        await client.connect();
        try {
          const entries = await client.list();
          context.logger.info("Listing {n} folders on {host}", {
            n: entries.length,
            host: cfg.host,
          });
          const folders = [];
          let totalMessages = 0;
          for (const e of entries) {
            let messages: number | null = null;
            let size: number | null = null;
            try {
              const st = await client.status(e.path, {
                messages: true,
                size: true,
              });
              messages = typeof st.messages === "number" ? st.messages : null;
              size = typeof st.size === "number" ? st.size : null;
              if (messages) totalMessages += messages;
            } catch (err) {
              context.logger.warning("STATUS failed for {path}: {err}", {
                path: e.path,
                err: err instanceof Error ? err.message : String(err),
              });
            }
            folders.push({
              path: e.path,
              name: e.name ?? null,
              delimiter: e.delimiter ? String(e.delimiter) : null,
              flags: flagsToArray(e.flags),
              subscribed: typeof e.subscribed === "boolean"
                ? e.subscribed
                : null,
              messages,
              size,
            });
          }
          const handle = await context.writeResource("folders", "tree", {
            totalFolders: folders.length,
            totalMessages,
            folders,
            retrievedAt: new Date().toISOString(),
          });
          return { dataHandles: [handle] };
        } finally {
          await client.logout();
        }
      },
    },
    sync: {
      description:
        "Snapshot message envelopes and a fixed set of headers (From, To, Cc, " +
        "Subject, Date, Message-ID, In-Reply-To, References, List-ID, " +
        "List-Unsubscribe, Auto-Submitted, Precedence) plus flags and size for " +
        "each folder. HEADERS ONLY -- no message bodies are fetched. Opens each " +
        "mailbox read-only (EXAMINE). Fans out over multiple folders in one run.",
      arguments: z.object({
        folder: z
          .union([z.string(), z.array(z.string())])
          .optional()
          .describe("Folder path(s) to snapshot; defaults to defaultFolder"),
        limit: z
          .number()
          .int()
          .positive()
          .optional()
          .describe("Cap the number of most-recent messages per folder"),
      }),
      execute: async (
        args: {
          folder?: string | string[];
          limit?: number;
          _client?: ClientFactory;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const client = (args._client ?? defaultClientFactory)(cfg);
        const targets = foldersArg(args.folder, cfg.defaultFolder);
        await client.connect();
        const handles: Array<{ name: string }> = [];
        try {
          for (const folder of targets) {
            const messages: Message[] = [];
            const box = await client.mailboxOpen(folder, { readOnly: true });
            try {
              const exists = typeof box.exists === "number" ? box.exists : 0;
              let range = "1:*";
              if (args.limit && exists > args.limit) {
                range = `${exists - args.limit + 1}:*`;
              }
              context.logger.info("Snapshotting {folder} ({exists} messages)", {
                folder,
                exists,
              });
              if (exists > 0) {
                for await (
                  const msg of client.fetch(range, {
                    uid: true,
                    envelope: true,
                    flags: true,
                    size: true,
                    headers: SYNC_HEADERS,
                  })
                ) {
                  messages.push(normalizeMessage(msg, folder));
                }
              }
            } finally {
              // Always release the mailbox, even if the fetch threw.
              await client.mailboxClose();
            }
            const handle = await context.writeResource(
              "snapshot",
              `snapshot:${folderSlug(folder)}`,
              {
                folder,
                scope: folder,
                count: messages.length,
                headersOnly: true,
                messages,
                retrievedAt: new Date().toISOString(),
              },
            );
            handles.push(handle);
          }
          return { dataHandles: handles };
        } finally {
          await client.logout();
        }
      },
    },
    fetchMessage: {
      description:
        "Fetch and DECODE the FULL body of specific messages by UID in ONE " +
        "folder. This is the ONE read method that pulls bodies -- sync is " +
        "header/envelope only. ONE folder per call: an IMAP UID is unique " +
        "only within one (folder,UIDVALIDITY), so the uidValidity guard and " +
        "the UID cap only mean anything scoped to a single mailbox. Opens the " +
        "folder read-only (EXAMINE) exactly like sync and ALWAYS closes it, " +
        "so it is STRUCTURALLY read-only: EXAMINE guarantees the server " +
        "refuses mutation and never sets \\Seen (there is no peek knob -- it " +
        "would be a silent no-op). Performs ZERO server mutation (not " +
        "dryRun-gated). Uses a PRE-FETCH SIZE GATE with TWO fan-out fetches " +
        "(never a per-UID loop): (1) one {uid,size} fetch to partition the " +
        "UID set against MAX_BODY_BYTES by the server's RFC822.SIZE, then (2) " +
        "one source fetch for the UNDER-cap UIDs only. An OVER-cap UID's body " +
        "is DELIBERATELY NOT pulled: its record is truncated=true, " +
        "sourceBytes=<server size>, null bodies -- so the oversized source is " +
        "never buffered and truncated honestly means 'body withheld for " +
        "size'. Under-cap (and no-server-size) UIDs are decoded with " +
        "postal-mime into one messageBody record each (text/html, attachment " +
        "METADATA only, extracted http/https links); a no-server-size body " +
        "over the cap is byte-truncated (never a UTF-16 char slice). Each " +
        "message's decode is isolated: a MIME-parse throw records that UID " +
        "with an error and null bodies and the batch continues. Stored html " +
        "is RAW and UNSANITIZED -- sanitization is deferred to any future " +
        "consumer. messageBody records have a FINITE lifetime so third-party " +
        "content does not persist indefinitely. Reuses the fail-closed " +
        "uidValidity guard (unverifiable == mismatch == refuse). Caps the UID " +
        "set at MAX_FETCH_UIDS. A UID absent from the folder, or one the " +
        "server reports with a null UID, is simply skipped, not an error.",
      arguments: z.object({
        folder: z.string().min(1).describe(
          "The ONE folder to fetch from (e.g. a sync snapshot:<folder>)",
        ),
        uids: z.array(z.number().int().positive()).describe(
          "UIDs to fetch; de-duplicated, capped at MAX_FETCH_UIDS, fanned out " +
            "in the two size/source fetches (never a per-UID loop)",
        ),
        uidValidity: z.number().int().positive().optional().describe(
          "If given, must match the folder's live UIDVALIDITY or the call " +
            "refuses with no read (fail-closed stale-selection guard)",
        ),
      }),
      execute: async (
        args: {
          folder: string;
          uids: number[];
          uidValidity?: number;
          _client?: ClientFactory;
          _parse?: MimeParser;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const folder = args.folder;
        const uids = dedupeUids(args.uids);
        checkFetchUidCap(uids);
        const cfg = context.globalArgs;
        const client = (args._client ?? defaultClientFactory)(cfg);
        const parse = args._parse ?? defaultParser;
        await client.connect();
        const handles: Array<{ name: string }> = [];
        try {
          // EXAMINE (read-only), exactly like sync -- never getMailboxLock.
          const box = await client.mailboxOpen(folder, { readOnly: true });
          try {
            // Fail-closed: an unverifiable guard is a mismatch, not a pass.
            checkUidValidity(box.uidValidity, args.uidValidity, folder);
            if (uids.length === 0) return { dataHandles: handles };
            context.logger.info(
              "Fetching {n} message bodies from {folder}",
              { n: uids.length, folder },
            );

            // FETCH 1 (fan-out): headers + RFC822.SIZE, NO source. Used to
            // partition by size and to build the header portion of each
            // record. Preserves first-seen (server) order via the array.
            const presentUids: number[] = [];
            const headerByUid = new Map<number, FetchMessage>();
            for await (
              const msg of client.fetch(
                uids.join(","),
                {
                  uid: true,
                  envelope: true,
                  flags: true,
                  size: true,
                  headers: SYNC_HEADERS,
                },
                { uid: true },
              )
            ) {
              if (typeof msg.uid !== "number") {
                // Never build an instance name on a null UID (FM-5).
                context.logger.warning(
                  "Skipping a message with no UID in {folder}",
                  { folder },
                );
                continue;
              }
              if (!headerByUid.has(msg.uid)) presentUids.push(msg.uid);
              headerByUid.set(msg.uid, msg);
            }

            // Partition present UIDs: an OVER-cap body (server size known and
            // over the cap) is withheld -- it does NOT go in the source fetch.
            const underCap: number[] = [];
            for (const uid of presentUids) {
              const size = headerByUid.get(uid)?.size;
              if (!(typeof size === "number" && size > MAX_BODY_BYTES)) {
                underCap.push(uid);
              }
            }

            // FETCH 2 (fan-out): source ONLY for the under-cap UIDs. Skipped
            // entirely when there are none (no empty-range fetch).
            const sourceByUid = new Map<number, Uint8Array | string>();
            if (underCap.length > 0) {
              for await (
                const msg of client.fetch(
                  underCap.join(","),
                  { uid: true, source: true },
                  { uid: true },
                )
              ) {
                if (typeof msg.uid === "number" && msg.source !== undefined) {
                  sourceByUid.set(msg.uid, msg.source);
                }
              }
            }

            // Build + persist one record per present UID, in server order.
            for (const uid of presentUids) {
              const hmsg = headerByUid.get(uid) as FetchMessage;
              const serverSize = typeof hmsg.size === "number"
                ? hmsg.size
                : undefined;
              const source = sourceByUid.get(uid);
              let record: MessageBody;
              try {
                // Per-message parse isolation (FM-3): one hostile/malformed
                // message must not abort the batch.
                record = await buildMessageBody(
                  hmsg,
                  folder,
                  source,
                  serverSize,
                  parse,
                );
              } catch (err) {
                context.logger.warning(
                  "Decode failed for UID {uid} in {folder}; recording error",
                  { uid, folder },
                );
                record = {
                  ...normalizeMessage(hmsg, folder),
                  text: null,
                  html: null,
                  attachments: [],
                  links: [],
                  truncated: false,
                  sourceBytes: source !== undefined
                    ? sourceByteLength(source)
                    : (serverSize ?? 0),
                  error: err instanceof Error ? err.message : String(err),
                  retrievedAt: new Date().toISOString(),
                };
              }
              const handle = await context.writeResource(
                "messageBody",
                `message:${folderSlug(folder)}:${uid}`,
                record,
              );
              handles.push(handle);
            }
          } finally {
            // Always release the mailbox, even if a fetch threw
            // (CLOSE-safe: EXAMINE never expunges).
            await client.mailboxClose();
          }
          return { dataHandles: handles };
        } finally {
          await client.logout();
        }
      },
    },
    addKeywords: {
      description:
        "Add custom IMAP keywords to a UID selection in one fan-out STORE " +
        "(+FLAGS) call. dryRun defaults to true: opens the mailbox read-only " +
        "(EXAMINE), computes a would-affect preview, performs ZERO mutation. " +
        "dryRun=false (the only mutate path) opens read-write via a mailbox " +
        "lock ONLY when something will change and releases it WITHOUT IMAP " +
        "CLOSE (no implicit expunge). Custom keywords only: the system-flag " +
        "namespace (leading backslash) is rejected. Idempotent: a keyword " +
        "already present is reported skipped, not re-sent. Applied evidence is " +
        "verified by a post-mutation re-FETCH (discrepancies[] on mismatch).",
      arguments: z.object({
        folder: z.string().min(1).describe("Mailbox to select"),
        uids: z.array(z.number().int().positive()).describe(
          "UIDs to act on (e.g. from a P1 snapshot:<folder>)",
        ),
        keywords: z.array(z.string().min(1)).min(1).describe(
          "Custom keywords to add; validated against the IMAP atom grammar " +
            "(system flags rejected)",
        ),
        dryRun: z.boolean().default(true).describe(
          "true (default): preview only, zero mutation. false: mutate.",
        ),
        uidValidity: z.number().int().positive().optional().describe(
          "If given, must match the mailbox's live UIDVALIDITY or the call " +
            "refuses with no mutation (stale-selection guard)",
        ),
      }),
      execute: async (
        args: {
          folder: string;
          uids: number[];
          keywords: string[];
          dryRun?: boolean;
          uidValidity?: number;
          _client?: ClientFactory;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const keywords = dedupeKeywords(args.keywords);
        for (const kw of keywords) validateKeyword(kw);
        const uids = dedupeUids(args.uids);
        checkUidCap(uids);
        const dryRun = args.dryRun ?? true;
        const cfg = context.globalArgs;
        const client = (args._client ?? defaultClientFactory)(cfg);
        const name = `addKeywords:${folderSlug(args.folder)}`;
        await client.connect();
        try {
          // PHASE 1 -- inspect under EXAMINE (read-only; CLOSE-safe).
          const { uidValidityOut, current } = await inspectKeywordState(
            client,
            args.folder,
            uids,
            args.uidValidity,
          );

          if (uids.length === 0) {
            const handle = await context.writeResource(
              "wouldAffect",
              name,
              wouldAffectRecord({
                op: "addKeywords",
                folder: args.folder,
                uidValidity: uidValidityOut,
                requestedCount: 0,
                resolvedCount: 0,
                count: 0,
                items: [],
                skipped: [],
                missingFromSource: [],
              }),
            );
            return { dataHandles: [handle] };
          }

          const { items, skipped, changedUids } = diffAddKeywords(
            args.folder,
            current,
            uids,
            keywords,
          );

          if (dryRun) {
            const handle = await context.writeResource(
              "wouldAffect",
              name,
              wouldAffectRecord({
                op: "addKeywords",
                folder: args.folder,
                uidValidity: uidValidityOut,
                requestedCount: uids.length,
                resolvedCount: current.size,
                count: changedUids.length,
                items,
                skipped,
                missingFromSource: [],
              }),
            );
            return { dataHandles: [handle] };
          }

          // dryRun=false but nothing changes: record a verified no-op WITHOUT
          // ever opening the mailbox read-write.
          if (changedUids.length === 0) {
            const handle = await context.writeResource(
              "applied",
              name,
              appliedRecord({
                op: "addKeywords",
                folder: args.folder,
                uidValidity: uidValidityOut,
                requestedCount: uids.length,
                resolvedCount: current.size,
                applied: 0,
                items,
                skipped,
                missingFromSource: [],
                discrepancies: [],
                serverResponses: [],
              }),
            );
            return { dataHandles: [handle] };
          }

          // PHASE 2 -- mutate under a read-write LOCK, released WITHOUT IMAP
          // CLOSE (lock.release()), so no implicit expunge is ever triggered.
          const lock = await client.getMailboxLock(args.folder, {
            readOnly: false,
          });
          try {
            checkUidValidity(lock.uidValidity, args.uidValidity, args.folder);
            assertNoUidValidityDrift(
              uidValidityOut,
              lock.uidValidity,
              args.folder,
            );

            context.logger.info(
              "Adding keywords {kw} to {n} UID(s) in {folder}",
              { kw: keywords, n: changedUids.length, folder: args.folder },
            );
            const serverResponses: unknown[] = [];
            try {
              serverResponses.push(
                await client.messageFlagsAdd(changedUids, keywords, {
                  uid: true,
                }),
              );
            } catch (err) {
              // CORR-4: the command may already have mutated server-side.
              // Record partial/error evidence BEFORE rethrowing.
              await context.writeResource(
                "applied",
                name,
                appliedRecord({
                  op: "addKeywords",
                  folder: args.folder,
                  uidValidity: uidValidityOut,
                  requestedCount: uids.length,
                  resolvedCount: current.size,
                  applied: 0,
                  items,
                  skipped,
                  missingFromSource: [],
                  discrepancies: changedUids.map((uid) => ({
                    uid,
                    reason:
                      "mutation threw after transmission; final state unverified",
                  })),
                  serverResponses,
                  error: err instanceof Error ? err.message : String(err),
                }),
              );
              throw err;
            }

            // CORR-3: re-FETCH the changed UIDs, record ACTUAL flags, and flag
            // any UID the server silently did not bring to its expected state.
            const discrepancies = await verifyKeywordMutation(
              client,
              changedUids,
              keywords,
              items,
              "add",
            );

            const handle = await context.writeResource(
              "applied",
              name,
              appliedRecord({
                op: "addKeywords",
                folder: args.folder,
                uidValidity: uidValidityOut,
                requestedCount: uids.length,
                resolvedCount: current.size,
                applied: changedUids.length - discrepancies.length,
                items,
                skipped,
                missingFromSource: [],
                discrepancies,
                serverResponses,
              }),
            );
            return { dataHandles: [handle] };
          } finally {
            lock.release();
          }
        } finally {
          await client.logout();
        }
      },
    },
    removeKeywords: {
      description:
        "Remove custom IMAP keywords from a UID selection in one fan-out " +
        "STORE (-FLAGS) call. dryRun defaults to true: opens the mailbox " +
        "read-only (EXAMINE), computes a would-affect preview, performs ZERO " +
        "mutation. dryRun=false (the only mutate path) opens read-write via a " +
        "mailbox lock ONLY when something will change and releases it WITHOUT " +
        "IMAP CLOSE (no implicit expunge). Custom keywords only: the " +
        "system-flag namespace (leading backslash) is rejected. Idempotent: a " +
        "keyword already absent is reported skipped. Applied evidence is " +
        "verified by a post-mutation re-FETCH (discrepancies[] on mismatch).",
      arguments: z.object({
        folder: z.string().min(1).describe("Mailbox to select"),
        uids: z.array(z.number().int().positive()).describe(
          "UIDs to act on (e.g. from a P1 snapshot:<folder>)",
        ),
        keywords: z.array(z.string().min(1)).min(1).describe(
          "Custom keywords to remove; validated against the IMAP atom grammar " +
            "(system flags rejected)",
        ),
        dryRun: z.boolean().default(true).describe(
          "true (default): preview only, zero mutation. false: mutate.",
        ),
        uidValidity: z.number().int().positive().optional().describe(
          "If given, must match the mailbox's live UIDVALIDITY or the call " +
            "refuses with no mutation (stale-selection guard)",
        ),
      }),
      execute: async (
        args: {
          folder: string;
          uids: number[];
          keywords: string[];
          dryRun?: boolean;
          uidValidity?: number;
          _client?: ClientFactory;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const keywords = dedupeKeywords(args.keywords);
        for (const kw of keywords) validateKeyword(kw);
        const uids = dedupeUids(args.uids);
        checkUidCap(uids);
        const dryRun = args.dryRun ?? true;
        const cfg = context.globalArgs;
        const client = (args._client ?? defaultClientFactory)(cfg);
        const name = `removeKeywords:${folderSlug(args.folder)}`;
        await client.connect();
        try {
          // PHASE 1 -- inspect under EXAMINE (read-only; CLOSE-safe).
          const { uidValidityOut, current } = await inspectKeywordState(
            client,
            args.folder,
            uids,
            args.uidValidity,
          );

          if (uids.length === 0) {
            const handle = await context.writeResource(
              "wouldAffect",
              name,
              wouldAffectRecord({
                op: "removeKeywords",
                folder: args.folder,
                uidValidity: uidValidityOut,
                requestedCount: 0,
                resolvedCount: 0,
                count: 0,
                items: [],
                skipped: [],
                missingFromSource: [],
              }),
            );
            return { dataHandles: [handle] };
          }

          const { items, skipped, changedUids } = diffRemoveKeywords(
            args.folder,
            current,
            uids,
            keywords,
          );

          if (dryRun) {
            const handle = await context.writeResource(
              "wouldAffect",
              name,
              wouldAffectRecord({
                op: "removeKeywords",
                folder: args.folder,
                uidValidity: uidValidityOut,
                requestedCount: uids.length,
                resolvedCount: current.size,
                count: changedUids.length,
                items,
                skipped,
                missingFromSource: [],
              }),
            );
            return { dataHandles: [handle] };
          }

          if (changedUids.length === 0) {
            const handle = await context.writeResource(
              "applied",
              name,
              appliedRecord({
                op: "removeKeywords",
                folder: args.folder,
                uidValidity: uidValidityOut,
                requestedCount: uids.length,
                resolvedCount: current.size,
                applied: 0,
                items,
                skipped,
                missingFromSource: [],
                discrepancies: [],
                serverResponses: [],
              }),
            );
            return { dataHandles: [handle] };
          }

          // PHASE 2 -- mutate under a read-write LOCK (release, no CLOSE).
          const lock = await client.getMailboxLock(args.folder, {
            readOnly: false,
          });
          try {
            checkUidValidity(lock.uidValidity, args.uidValidity, args.folder);
            assertNoUidValidityDrift(
              uidValidityOut,
              lock.uidValidity,
              args.folder,
            );

            context.logger.info(
              "Removing keywords {kw} from {n} UID(s) in {folder}",
              { kw: keywords, n: changedUids.length, folder: args.folder },
            );
            const serverResponses: unknown[] = [];
            try {
              serverResponses.push(
                await client.messageFlagsRemove(changedUids, keywords, {
                  uid: true,
                }),
              );
            } catch (err) {
              await context.writeResource(
                "applied",
                name,
                appliedRecord({
                  op: "removeKeywords",
                  folder: args.folder,
                  uidValidity: uidValidityOut,
                  requestedCount: uids.length,
                  resolvedCount: current.size,
                  applied: 0,
                  items,
                  skipped,
                  missingFromSource: [],
                  discrepancies: changedUids.map((uid) => ({
                    uid,
                    reason:
                      "mutation threw after transmission; final state unverified",
                  })),
                  serverResponses,
                  error: err instanceof Error ? err.message : String(err),
                }),
              );
              throw err;
            }

            // CORR-3: re-FETCH changed UIDs, record ACTUAL flags, flag any UID
            // that still carries a keyword that should have been removed.
            const discrepancies = await verifyKeywordMutation(
              client,
              changedUids,
              keywords,
              items,
              "remove",
            );

            const handle = await context.writeResource(
              "applied",
              name,
              appliedRecord({
                op: "removeKeywords",
                folder: args.folder,
                uidValidity: uidValidityOut,
                requestedCount: uids.length,
                resolvedCount: current.size,
                applied: changedUids.length - discrepancies.length,
                items,
                skipped,
                missingFromSource: [],
                discrepancies,
                serverResponses,
              }),
            );
            return { dataHandles: [handle] };
          } finally {
            lock.release();
          }
        } finally {
          await client.logout();
        }
      },
    },
    move: {
      description:
        "Move a UID selection from `folder` to `destination` in one fan-out " +
        "MOVE call. dryRun defaults to true: opens the source read-only " +
        "(EXAMINE), computes a would-affect preview, performs ZERO mutation. " +
        "dryRun=false (the only mutate path) opens the source read-write via a " +
        "mailbox lock ONLY when something will move and releases it WITHOUT " +
        "IMAP CLOSE (no implicit expunge). UIDs present in the source are " +
        "moved; UIDs absent from the source are reported DISTINCTLY under " +
        "`missingFromSource` (an anomaly: expunged or moved elsewhere, NOT " +
        "confirmed converged), never conflated with success. Rejects a " +
        "self-move (destination === folder). Applied evidence is verified by " +
        "re-checking source absence after the move (discrepancies[]).",
      arguments: z.object({
        folder: z.string().min(1).describe("Source mailbox to select"),
        uids: z.array(z.number().int().positive()).describe(
          "UIDs to move (e.g. from a P1 snapshot:<folder>)",
        ),
        destination: z.string().min(1).describe("Destination mailbox path"),
        dryRun: z.boolean().default(true).describe(
          "true (default): preview only, zero mutation. false: mutate.",
        ),
        uidValidity: z.number().int().positive().optional().describe(
          "If given, must match the source mailbox's live UIDVALIDITY or " +
            "the call refuses with no mutation (stale-selection guard)",
        ),
      }),
      execute: async (
        args: {
          folder: string;
          uids: number[];
          destination: string;
          dryRun?: boolean;
          uidValidity?: number;
          _client?: ClientFactory;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        // CORR-5: a self-move is server-unspecified (error or UID-reassigning
        // no-op); refuse it outright.
        if (args.destination === args.folder) {
          throw new Error(
            `Refusing to move within a single folder: destination ` +
              `("${args.destination}") must differ from the source folder.`,
          );
        }
        const uids = dedupeUids(args.uids);
        checkUidCap(uids);
        const dryRun = args.dryRun ?? true;
        const cfg = context.globalArgs;
        const client = (args._client ?? defaultClientFactory)(cfg);
        const name = `move:${folderSlug(args.folder)}->${
          folderSlug(args.destination)
        }`;
        await client.connect();
        try {
          // PHASE 1 -- inspect source presence under EXAMINE (CLOSE-safe).
          const { uidValidityOut, present } = await inspectPresence(
            client,
            args.folder,
            uids,
            args.uidValidity,
          );

          if (uids.length === 0) {
            const handle = await context.writeResource(
              "wouldAffect",
              name,
              wouldAffectRecord({
                op: "move",
                folder: args.folder,
                destination: args.destination,
                uidValidity: uidValidityOut,
                requestedCount: 0,
                resolvedCount: 0,
                count: 0,
                items: [],
                skipped: [],
                missingFromSource: [],
              }),
            );
            return { dataHandles: [handle] };
          }

          const { items, missingFromSource, moveUids } = diffMove(
            args.folder,
            args.destination,
            present,
            uids,
          );

          if (dryRun) {
            const handle = await context.writeResource(
              "wouldAffect",
              name,
              wouldAffectRecord({
                op: "move",
                folder: args.folder,
                destination: args.destination,
                uidValidity: uidValidityOut,
                requestedCount: uids.length,
                resolvedCount: present.size,
                count: moveUids.length,
                items,
                skipped: [],
                missingFromSource,
              }),
            );
            return { dataHandles: [handle] };
          }

          if (moveUids.length === 0) {
            const handle = await context.writeResource(
              "applied",
              name,
              appliedRecord({
                op: "move",
                folder: args.folder,
                destination: args.destination,
                uidValidity: uidValidityOut,
                requestedCount: uids.length,
                resolvedCount: present.size,
                applied: 0,
                items,
                skipped: [],
                missingFromSource,
                discrepancies: [],
                serverResponses: [],
              }),
            );
            return { dataHandles: [handle] };
          }

          // PHASE 2 -- mutate under a read-write LOCK (release, no CLOSE).
          const lock = await client.getMailboxLock(args.folder, {
            readOnly: false,
          });
          try {
            checkUidValidity(lock.uidValidity, args.uidValidity, args.folder);
            assertNoUidValidityDrift(
              uidValidityOut,
              lock.uidValidity,
              args.folder,
            );

            context.logger.info(
              "Moving {n} UID(s) from {folder} to {destination}",
              {
                n: moveUids.length,
                folder: args.folder,
                destination: args.destination,
              },
            );
            const serverResponses: unknown[] = [];
            try {
              serverResponses.push(
                await client.messageMove(moveUids, args.destination, {
                  uid: true,
                }),
              );
            } catch (err) {
              await context.writeResource(
                "applied",
                name,
                appliedRecord({
                  op: "move",
                  folder: args.folder,
                  destination: args.destination,
                  uidValidity: uidValidityOut,
                  requestedCount: uids.length,
                  resolvedCount: present.size,
                  applied: 0,
                  items,
                  skipped: [],
                  missingFromSource,
                  discrepancies: moveUids.map((uid) => ({
                    uid,
                    reason:
                      "move threw after transmission; final state unverified",
                  })),
                  serverResponses,
                  error: err instanceof Error ? err.message : String(err),
                }),
              );
              throw err;
            }

            // CORR-3: re-check source absence for the moved UIDs. The source is
            // still selected under the lock; any UID STILL present did not move.
            const discrepancies = await verifyMoveMutation(client, moveUids);

            const handle = await context.writeResource(
              "applied",
              name,
              appliedRecord({
                op: "move",
                folder: args.folder,
                destination: args.destination,
                uidValidity: uidValidityOut,
                requestedCount: uids.length,
                resolvedCount: present.size,
                applied: moveUids.length - discrepancies.length,
                items,
                skipped: [],
                missingFromSource,
                discrepancies,
                serverResponses,
              }),
            );
            return { dataHandles: [handle] };
          } finally {
            lock.release();
          }
        } finally {
          await client.logout();
        }
      },
    },
    applyTagPlan: {
      description:
        "Apply a @shrug/mail-ontology tagPlan: reads the LATEST `tagPlan` " +
        "record from `ontologyModel` (never recomputes classification) and " +
        "applies it in two fan-outs -- ONE addKeywords-equivalent STORE per " +
        "distinct (folder,keyword) group, and ONE move-equivalent MOVE per " +
        "distinct (folder,destination) group -- never a per-message loop. " +
        "Every group goes through the SAME safety core as addKeywords/move: " +
        "two-phase EXAMINE/lock open, uidValidity + drift guard, MAX_UIDS- " +
        "capped chunking (a group over the cap is split into multiple fan-out " +
        "calls, never rejected), and post-mutation re-FETCH verification. " +
        "Every tagPlan keyword is re-validated via validateKeyword before any " +
        "connection is made; one invalid keyword aborts the whole run. " +
        "dryRun defaults to true (zero mutation, consolidated wouldAffect-" +
        "shaped preview); dryRun=false is the sole mutate path and is " +
        "expected to be operationally gated outside this type, same as the " +
        "P3 methods.",
      arguments: z.object({
        ontologyModel: z.string().min(1).describe(
          "The @shrug/mail-ontology instance whose latest tagPlan to apply",
        ),
        dryRun: z.boolean().default(true).describe(
          "true (default): preview only, zero mutation. false: mutate.",
        ),
        folders: z.array(z.string()).optional().describe(
          "Restrict to these source folders (optional; default is every " +
            "folder present in the tagPlan)",
        ),
        applyMoves: z.boolean().default(true).describe(
          "Set false to tag-only and skip Finance moves entirely",
        ),
      }),
      execute: async (
        args: {
          ontologyModel: string;
          dryRun?: boolean;
          folders?: string[];
          applyMoves?: boolean;
          _plan?: TagPlanItem[];
          _client?: ClientFactory;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const dryRun = args.dryRun ?? true;
        const applyMoves = args.applyMoves ?? true;
        const name = "applyTagPlan";

        // 1. Load the tagPlan -- `_plan` is the test seam (bypasses the
        // cross-model read entirely; repo rule 3: never recompute, only read).
        // ATP-2: the live decode also surfaces how many entries it dropped as
        // structurally malformed, so cross-model drift is visible.
        let rawItems: TagPlanItem[];
        let droppedCount = 0;
        if (args._plan !== undefined) {
          rawItems = args._plan;
        } else {
          const records = await context.readModelData(
            args.ontologyModel,
            "tagPlan",
          );
          const decoded = toTagPlanItems(records[records.length - 1]);
          rawItems = decoded.items;
          droppedCount = decoded.droppedCount;
        }

        // 2. Optional folder filter.
        const folderFilter = args.folders ? new Set(args.folders) : undefined;
        const items = folderFilter
          ? rawItems.filter((it) => folderFilter.has(it.folder))
          : rawItems;

        // 3. Defense-in-depth: re-validate EVERY keyword in scope BEFORE
        // connecting or mutating anything. Abort the whole run (no partial
        // mutation) on the first invalid keyword rather than silently
        // dropping it -- tagPlan already sanitizes, but trust-but-verify
        // across the module boundary.
        for (const it of items) {
          for (const kw of it.keywords) validateKeyword(kw);
        }

        // 4. Group: KEYWORDS by (folder, keyword) -- only items that actually
        // carry a keyword create a group; MOVES by (folder, destination),
        // skipped entirely when applyMoves=false. A (folder, folder)
        // "self-move" group is refused outright, mirroring move's own CORR-5
        // self-move guard (server-unspecified behavior). Grouping happens
        // BEFORE any connection, so the self-move abort never opens a session.
        const keywordGroupUids = new Map<string, Map<string, number[]>>();
        for (const it of items) {
          const kws = dedupeKeywords(it.keywords);
          if (kws.length === 0) continue;
          let byKeyword = keywordGroupUids.get(it.folder);
          if (!byKeyword) {
            byKeyword = new Map();
            keywordGroupUids.set(it.folder, byKeyword);
          }
          for (const kw of kws) {
            const list = byKeyword.get(kw) ?? [];
            list.push(it.uid);
            byKeyword.set(kw, list);
          }
        }
        const moveGroupUids = new Map<string, Map<string, number[]>>();
        if (applyMoves) {
          for (const it of items) {
            if (it.financeMove === null) continue;
            if (it.financeMove === it.folder) {
              throw new Error(
                `Refusing to move within a single folder: tagPlan entry for ` +
                  `uid ${it.uid} in "${it.folder}" names its own folder as ` +
                  `financeMove.`,
              );
            }
            let byDest = moveGroupUids.get(it.folder);
            if (!byDest) {
              byDest = new Map();
              moveGroupUids.set(it.folder, byDest);
            }
            const list = byDest.get(it.financeMove) ?? [];
            list.push(it.uid);
            byDest.set(it.financeMove, list);
          }
        }

        let keywordGroupCount = 0;
        for (const bk of keywordGroupUids.values()) {
          keywordGroupCount += bk.size;
        }
        let moveGroupCount = 0;
        for (const bd of moveGroupUids.values()) moveGroupCount += bd.size;

        // Totals builders, shared by the preview, applied, and partial-error
        // paths so the three never drift apart.
        const previewTotals = (
          kw: NonNullable<KeywordGroupResult["preview"]>[],
          mv: NonNullable<MoveGroupResult["preview"]>[],
        ) => ({
          keywordGroupCount: kw.length,
          moveGroupCount: mv.length,
          added: kw.reduce((n, g) => n + g.addCount, 0),
          alreadyPresent: kw.reduce((n, g) => n + g.alreadyPresentCount, 0),
          notFound: kw.reduce((n, g) => n + g.notFound, 0),
          moved: mv.reduce((n, g) => n + (g.uidCount - g.missingFromSource), 0),
          missingFromSource: mv.reduce((n, g) => n + g.missingFromSource, 0),
          discrepancies: 0,
        });
        const appliedTotals = (
          kw: NonNullable<KeywordGroupResult["applied"]>[],
          mv: NonNullable<MoveGroupResult["applied"]>[],
        ) => ({
          keywordGroupCount: kw.length,
          moveGroupCount: mv.length,
          added: kw.reduce((n, g) => n + g.appliedCount, 0),
          alreadyPresent: kw.reduce((n, g) => n + g.alreadyPresentCount, 0),
          notFound: kw.reduce((n, g) => n + g.notFound, 0),
          moved: mv.reduce((n, g) => n + g.appliedCount, 0),
          missingFromSource: mv.reduce((n, g) => n + g.missingFromSource, 0),
          discrepancies: kw.reduce((n, g) => n + g.discrepancies.length, 0) +
            mv.reduce((n, g) => n + g.discrepancies.length, 0),
        });

        // 5. ATP-4: no actionable groups (a 0-item plan, OR a non-empty plan
        // whose every item has no keyword and no move) -> explicit empty
        // preview/applied WITHOUT opening a connection. droppedCount still
        // surfaces so decode drift is never hidden by the fast path.
        if (keywordGroupCount === 0 && moveGroupCount === 0) {
          const handle = await context.writeResource(
            dryRun ? "tagPlanPreview" : "tagPlanApplied",
            name,
            {
              generatedAt: new Date().toISOString(),
              ontologyModel: args.ontologyModel,
              dryRun,
              droppedCount,
              keywordGroups: [],
              moveGroups: [],
              totals: dryRun ? previewTotals([], []) : appliedTotals([], []),
            },
          );
          return { dataHandles: [handle] };
        }

        const cfg = context.globalArgs;
        const client = (args._client ?? defaultClientFactory)(cfg);
        await client.connect();
        // Accumulators declared OUTSIDE the try so the NEW-2 partial-failure
        // path can persist whatever completed before a mid-run throw.
        const keywordPreviews: NonNullable<KeywordGroupResult["preview"]>[] =
          [];
        const keywordApplied: NonNullable<KeywordGroupResult["applied"]>[] = [];
        const movePreviews: NonNullable<MoveGroupResult["preview"]>[] = [];
        const moveApplied: NonNullable<MoveGroupResult["applied"]>[] = [];
        try {
          for (const [folder, byKeyword] of keywordGroupUids) {
            for (const [keyword, uidsRaw] of byKeyword) {
              const result = await processKeywordGroup(
                client,
                folder,
                keyword,
                dedupeUids(uidsRaw),
                dryRun,
              );
              if (result.preview) keywordPreviews.push(result.preview);
              if (result.applied) keywordApplied.push(result.applied);
            }
          }

          for (const [folder, byDest] of moveGroupUids) {
            for (const [destination, uidsRaw] of byDest) {
              const result = await processMoveGroup(
                client,
                folder,
                destination,
                dedupeUids(uidsRaw),
                dryRun,
              );
              if (result.preview) movePreviews.push(result.preview);
              if (result.applied) moveApplied.push(result.applied);
            }
          }
        } catch (err) {
          // NEW-2: a group's fan-out threw mid-run. On the mutate path this
          // means earlier groups may have already changed live mail -- persist
          // the PARTIAL evidence (every group that completed + the error)
          // BEFORE rethrowing, so the audit trail is never lost. (dryRun makes
          // no mutations, so there is nothing to salvage there -- just
          // propagate.)
          if (!dryRun) {
            await context.writeResource("tagPlanApplied", name, {
              generatedAt: new Date().toISOString(),
              ontologyModel: args.ontologyModel,
              dryRun: false,
              droppedCount,
              keywordGroups: keywordApplied,
              moveGroups: moveApplied,
              totals: appliedTotals(keywordApplied, moveApplied),
              error: err instanceof Error ? err.message : String(err),
            });
          }
          throw err;
        } finally {
          await client.logout();
        }

        const generatedAt = new Date().toISOString();
        if (dryRun) {
          const handle = await context.writeResource("tagPlanPreview", name, {
            generatedAt,
            ontologyModel: args.ontologyModel,
            dryRun: true,
            droppedCount,
            keywordGroups: keywordPreviews,
            moveGroups: movePreviews,
            totals: previewTotals(keywordPreviews, movePreviews),
          });
          return { dataHandles: [handle] };
        }

        const handle = await context.writeResource("tagPlanApplied", name, {
          generatedAt,
          ontologyModel: args.ontologyModel,
          dryRun: false,
          droppedCount,
          keywordGroups: keywordApplied,
          moveGroups: moveApplied,
          totals: appliedTotals(keywordApplied, moveApplied),
        });
        return { dataHandles: [handle] };
      },
    },
    createFolder: {
      description:
        "Ensure a list of mailbox paths exist, fanned out over the entire " +
        "list in ONE call (never N per-folder calls, capped at MAX_FOLDERS). " +
        "dryRun defaults to true: lists the live folder tree, computes a " +
        "per-folder exists-vs-would-create preview, performs ZERO mutation. " +
        "dryRun=false (the only mutate path) calls imapflow mailboxCreate " +
        "for each folder NOT already present; a folder already present is " +
        "skipped entirely (idempotent no-op -- no create call is made for " +
        "it). An ALREADYEXISTS server response on create is treated as " +
        "SUCCESS, not an error (imapflow itself normalizes this to " +
        "created:false; isAlreadyExistsError is defense-in-depth on top of " +
        "that). Each item records the server-CANONICAL path (imapflow " +
        "normalizes namespace prefixes, so both LIST and mailboxCreate " +
        "return the prefixed path); the post-creation re-LIST compares on " +
        "that canonical path, so a successful create under a namespace " +
        "prefix is never misreported as a discrepancy. After creating, " +
        "every requested folder is re-verified against a fresh LIST; any " +
        "folder still absent is recorded under discrepancies[]. Every path " +
        "is validated (non-empty, no leading/trailing whitespace, no " +
        "control characters) before any connection is made -- one invalid " +
        "path aborts the whole call with zero mutation. Uses the server's " +
        "LIVE hierarchy delimiter (from LIST), echoed in the resource; " +
        "never hardcodes a delimiter. This is a mailbox-level op: it does " +
        "not need the per-UID getMailboxLock/uidValidity machinery the " +
        "message methods use. Both a mailboxCreate failure mid-batch (not " +
        "ALREADYEXISTS) AND a Phase-2 re-LIST/verification failure persist " +
        "the folders already processed plus the error BEFORE rethrowing " +
        "(mirrors applyTagPlan's NEW-2) -- the audit is never left empty " +
        "on throw, even for live mutations already applied.",
      arguments: z.object({
        folders: z.array(z.string()).min(1).describe(
          "Mailbox paths to ensure exist; each validated (non-empty, no " +
            "leading/trailing whitespace, no control characters) before any " +
            "connection is made. Capped at MAX_FOLDERS per call.",
        ),
        dryRun: z.boolean().default(true).describe(
          "true (default): preview only, zero mutation. false: create " +
            "every absent folder.",
        ),
      }),
      execute: async (
        args: {
          folders: string[];
          dryRun?: boolean;
          _client?: ClientFactory;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        // Validate every path BEFORE connecting: one invalid path aborts the
        // whole call with zero mutation (same abort-before-connect pattern
        // as applyTagPlan's keyword re-validation).
        for (const f of args.folders) validateFolderPath(f);
        const folders = [...new Set(args.folders)];
        checkFolderCap(folders);
        const dryRun = args.dryRun ?? true;
        const cfg = context.globalArgs;
        const client = (args._client ?? defaultClientFactory)(cfg);
        const name = "createFolder";
        await client.connect();
        try {
          // PHASE 1 -- inspect the live folder tree. createFolder is
          // mailbox-level: this (not mailboxOpen/EXAMINE) is its entire
          // "inspect" phase, and it performs no mutation.
          const { existingPaths, delimiter } = await listFolderPaths(client);

          if (dryRun) {
            const items = folders.map((folder) => {
              const existsAlready = existingPaths.has(folder);
              return { folder, existsAlready, wouldCreate: !existsAlready };
            });
            context.logger.info(
              "createFolder preview: {n} requested, {c} would create",
              {
                n: folders.length,
                c: items.filter((i) => i.wouldCreate).length,
              },
            );
            const handle = await context.writeResource(
              "createFolderPreview",
              name,
              createFolderPreviewRecord({ delimiter, items }),
            );
            return { dataHandles: [handle] };
          }

          // dryRun=false. Accumulators declared OUTSIDE the try so the
          // partial-failure path (CF-1) can persist whatever completed
          // before a throw -- whether the throw came from a mailboxCreate in
          // the create loop OR from the Phase-2 re-LIST/verification after
          // folders were already created live.
          const items: CreateFolderResultItem[] = [];
          const serverResponses: unknown[] = [];
          const discrepancies: Array<{ folder: string; reason: string }> = [];
          try {
            // CF-4: ONE pass over folders in the caller's (de-duplicated)
            // order, branching per element, so items[] lines up with the
            // request order rather than skipped-first-then-absent.
            // Already-present folders are skipped entirely: NO mailboxCreate
            // call (idempotent no-op). The pre-check is advisory -- under a
            // namespace prefix the raw-vs-canonical mismatch may miss an
            // existing folder, which is harmless because the create then
            // returns ALREADYEXISTS (handled below).
            for (const folder of folders) {
              if (existingPaths.has(folder)) {
                items.push({
                  folder,
                  canonicalPath: folder,
                  existedBefore: true,
                  created: false,
                  alreadyExisted: true,
                  verifiedExists: true,
                });
                continue;
              }
              try {
                const resp = await client.mailboxCreate(folder);
                serverResponses.push(resp);
                // CF-2: resp.path is the imapflow-NORMALIZED (namespace-
                // prefixed) path; carry it as the canonical path and compare
                // Phase-2 against IT, never the raw request.
                const canonicalPath = resp.path;
                if (resp.created) {
                  context.logger.info("Created folder {folder}", { folder });
                  items.push({
                    folder,
                    canonicalPath,
                    existedBefore: false,
                    created: true,
                    // verifiedExists corrected by the Phase-2 re-LIST below.
                    alreadyExisted: false,
                    verifiedExists: true,
                  });
                } else {
                  // ALREADYEXISTS, normalized by imapflow to created:false --
                  // a race with another session, not an error.
                  items.push({
                    folder,
                    canonicalPath,
                    existedBefore: false,
                    created: false,
                    alreadyExisted: true,
                    verifiedExists: true,
                  });
                }
              } catch (err) {
                // Defense-in-depth: a client that throws instead of
                // normalizing ALREADYEXISTS is still treated as success. The
                // throw carries no resp.path, so the raw request is the best
                // available canonical path here.
                if (isAlreadyExistsError(err)) {
                  items.push({
                    folder,
                    canonicalPath: folder,
                    existedBefore: false,
                    created: false,
                    alreadyExisted: true,
                    verifiedExists: true,
                  });
                  continue;
                }
                throw err;
              }
            }

            // PHASE 2 -- post-creation verification: re-LIST and confirm
            // every requested folder actually exists now, compared on the
            // server-canonical path (CF-2). Never trust the create call's
            // own report alone. This re-LIST and the comparison run INSIDE
            // the try (CF-1): if the re-LIST throws after live creates, the
            // catch below persists the evidence rather than losing it.
            const { existingPaths: verifiedPaths } = await listFolderPaths(
              client,
            );
            for (const it of items) {
              const stillThere = verifiedPaths.has(it.canonicalPath);
              it.verifiedExists = stillThere;
              if (!stillThere) {
                discrepancies.push({
                  folder: it.folder,
                  reason: "requested but still absent after create",
                });
              }
            }
          } catch (err) {
            // Mirrors applyTagPlan's NEW-2 (CF-1): a mailboxCreate OR the
            // Phase-2 re-LIST threw after folders may already have been
            // created live. Persist the folders already processed plus the
            // error BEFORE rethrowing, so the audit is never left empty on
            // throw. discrepancies may be partial/empty (Phase-2 may not
            // have completed) -- the error field marks this as a partial
            // record.
            await context.writeResource(
              "createFolderResult",
              name,
              createFolderResultRecord({
                delimiter,
                requestedCount: folders.length,
                items,
                discrepancies,
                serverResponses,
                error: err instanceof Error ? err.message : String(err),
              }),
            );
            throw err;
          }

          const handle = await context.writeResource(
            "createFolderResult",
            name,
            createFolderResultRecord({
              delimiter,
              requestedCount: folders.length,
              items,
              discrepancies,
              serverResponses,
            }),
          );
          return { dataHandles: [handle] };
        } finally {
          await client.logout();
        }
      },
    },
  },
};
