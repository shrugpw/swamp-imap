/**
 * Unit tests for the read-only @shrug/imap model.
 *
 * Every test injects a synthetic in-memory client through the `_client` seam --
 * no live IMAP server is contacted. All fixtures are depersonalized: addresses
 * use example.com / RFC 2606 reserved domains, never real mailbox contents.
 *
 * @module
 */
import { assertEquals, assertRejects, assertThrows } from "jsr:@std/assert@1";
import { z } from "npm:zod@4";
import {
  buildMessageBody,
  checkFetchUidCap,
  checkUidValidity,
  type ClientFactory,
  type DataRecord,
  defaultClientFactory,
  defaultParser,
  extractLinks,
  type FetchMessage,
  type FetchQuery,
  flagsToArray,
  folderSlug,
  type ImapClientLike,
  isAlreadyExistsError,
  type ListEntry,
  type MailboxLock,
  type MailboxOpenResult,
  type MailboxStatus,
  MAX_BODY_BYTES,
  MAX_FETCH_UIDS,
  MAX_FOLDERS,
  MAX_UIDS,
  type Message,
  type MimeParser,
  model,
  normalizeAddresses,
  normalizeMessage,
  parseHeaderBlock,
  SOURCE_NOT_RETURNED,
  sourceByteLength,
  type StatusQuery,
  SYNC_HEADERS,
  type TagPlanItem,
  toTagPlanItems,
  truncateUtf8ToBytes,
  validateFolderPath,
  validateKeyword,
} from "./imap.ts";

// ---------------------------------------------------------------------------
// Synthetic fixtures (depersonalized)
// ---------------------------------------------------------------------------

const FOLDERS: ListEntry[] = [
  {
    path: "INBOX",
    name: "INBOX",
    delimiter: "/",
    flags: new Set(["\\HasNoChildren"]),
    subscribed: true,
  },
  {
    path: "Archive",
    name: "Archive",
    delimiter: "/",
    flags: new Set(["\\HasNoChildren"]),
    subscribed: true,
  },
];

const STATUS: Record<string, MailboxStatus> = {
  INBOX: { messages: 2, size: 4096 },
  Archive: { messages: 0, size: 0 },
};

const INBOX_MESSAGES: FetchMessage[] = [
  {
    uid: 101,
    flags: new Set(["\\Seen"]),
    size: 2048,
    envelope: {
      from: [{ name: "Alice Example", address: "alice@example.com" }],
      to: [{ name: "Test User", address: "user@example.net" }],
      cc: [],
      subject: "Hello there",
      date: new Date("2026-01-02T03:04:05.000Z"),
      messageId: "<msg-101@example.com>",
      inReplyTo: undefined,
    },
    headers: "References: <root@example.com>\r\nPrecedence: list\r\n" +
      "List-Id: Example Discuss <discuss.example.com>\r\n" +
      "List-Unsubscribe: <mailto:unsub@example.com>\r\n" +
      "List-Post: <mailto:discuss@example.com>\r\n" +
      "Reply-To: Example Discuss <discuss@example.com>\r\n",
  },
  {
    uid: 102,
    flags: ["\\Flagged"],
    size: 2048,
    envelope: {
      from: [{ name: "Bot", address: "noreply@example.org" }],
      to: [{ address: "user@example.net" }],
      subject: "Automated notice",
      date: "2026-01-03T00:00:00.000Z",
      messageId: "<msg-102@example.org>",
    },
    headers: new TextEncoder().encode(
      "Auto-Submitted: auto-generated\r\n",
    ),
  },
];

/**
 * A scripted, read-only client. Records whether EXAMINE (read-only) was asked
 * for, the last fetch query, and how many times a mailbox was closed / the
 * session logged out. Serves messages for the currently open folder.
 */
class ScriptedClient implements ImapClientLike {
  openedReadOnly: boolean[] = [];
  closedCount = 0;
  loggedOut = false;
  lastFetchQuery: Record<string, unknown> | null = null;
  lastRange: string | null = null;
  private openFolder = "";

  constructor(
    private readonly messagesByFolder: Record<string, FetchMessage[]>,
  ) {}

  connect(): Promise<void> {
    return Promise.resolve();
  }
  list(): Promise<ListEntry[]> {
    return Promise.resolve(FOLDERS);
  }
  status(path: string, _query: StatusQuery): Promise<MailboxStatus> {
    return Promise.resolve(STATUS[path] ?? {});
  }
  mailboxOpen(
    path: string,
    opts: { readOnly: boolean },
  ): Promise<{ exists?: number }> {
    this.openFolder = path;
    this.openedReadOnly.push(opts.readOnly);
    return Promise.resolve({
      exists: (this.messagesByFolder[path] ?? []).length,
    });
  }
  async *fetch(
    range: string,
    query: FetchQuery,
  ): AsyncIterable<FetchMessage> {
    this.lastRange = range;
    this.lastFetchQuery = query as unknown as Record<string, unknown>;
    for (const m of this.messagesByFolder[this.openFolder] ?? []) {
      yield await Promise.resolve(m);
    }
  }
  mailboxClose(): Promise<void> {
    this.closedCount++;
    return Promise.resolve();
  }
  logout(): Promise<void> {
    this.loggedOut = true;
    return Promise.resolve();
  }
  // This fixture only ever backs the read-only methods (listFolders/sync) in
  // this file's tests; the mutating members exist solely to satisfy
  // ImapClientLike and must never be reached from a read-path test.
  messageFlagsAdd(): Promise<unknown> {
    throw new Error("ScriptedClient (read-only fixture) has no write support");
  }
  messageFlagsRemove(): Promise<unknown> {
    throw new Error("ScriptedClient (read-only fixture) has no write support");
  }
  messageMove(): Promise<unknown> {
    throw new Error("ScriptedClient (read-only fixture) has no write support");
  }
  getMailboxLock(): Promise<MailboxLock> {
    throw new Error(
      "ScriptedClient (read-only fixture) never opens read-write",
    );
  }
  mailboxCreate(): Promise<{ path: string; created: boolean }> {
    throw new Error("ScriptedClient (read-only fixture) has no write support");
  }
}

/**
 * Collect the writeResource calls a method makes. `readModelData` is a
 * throwing stub here: every read/write-path test in this file injects its
 * tagPlan (when applicable) via the `_plan` seam, so applyTagPlan's
 * cross-model read is never exercised against this context -- a call here
 * would indicate a test accidentally exercising the live-read path.
 */
function makeContext() {
  const writes: Array<
    { spec: string; name: string; data: Record<string, unknown> }
  > = [];
  const context = {
    globalArgs: {
      host: "imap.example.com",
      port: 993,
      user: "user@example.net",
      password: "unused-in-tests",
      secure: true,
      allowInsecure: false,
      defaultFolder: "INBOX",
    },
    logger: { info() {}, warning() {} },
    readModelData: (
      _model: string,
      _spec?: string,
    ): Promise<DataRecord[]> => {
      throw new Error(
        "readModelData should not be called in these tests -- inject the " +
          "tagPlan via the _plan seam instead",
      );
    },
    writeResource: (
      spec: string,
      name: string,
      data: Record<string, unknown>,
    ) => {
      writes.push({ spec, name, data });
      return Promise.resolve({ name });
    },
  };
  return { context, writes };
}

// ---------------------------------------------------------------------------
// Pure-helper tests
// ---------------------------------------------------------------------------

Deno.test("flagsToArray handles Set, array, and undefined", () => {
  assertEquals(flagsToArray(new Set(["\\Seen", "\\Flagged"])).sort(), [
    "\\Flagged",
    "\\Seen",
  ]);
  assertEquals(flagsToArray(["\\Draft"]), ["\\Draft"]);
  assertEquals(flagsToArray(undefined), []);
});

Deno.test("normalizeAddresses fills nulls for missing parts", () => {
  assertEquals(
    normalizeAddresses([{ name: "A", address: "a@example.com" }, {
      address: "b@example.com",
    }]),
    [
      { name: "A", address: "a@example.com" },
      { name: null, address: "b@example.com" },
    ],
  );
  assertEquals(normalizeAddresses(undefined), []);
});

Deno.test("parseHeaderBlock unfolds continuations and lowercases keys", () => {
  const raw = "References: <a@example.com>\r\n <b@example.com>\r\n" +
    "List-ID: Example <l.example.com>\r\n";
  const h = parseHeaderBlock(raw);
  assertEquals(h["references"], "<a@example.com> <b@example.com>");
  assertEquals(h["list-id"], "Example <l.example.com>");
});

Deno.test("parseHeaderBlock accepts Uint8Array and absent input", () => {
  const h = parseHeaderBlock(new TextEncoder().encode("Precedence: bulk\r\n"));
  assertEquals(h["precedence"], "bulk");
  assertEquals(parseHeaderBlock(undefined), {});
});

Deno.test("normalizeMessage maps envelope + headers, no body field", () => {
  const m: Message = normalizeMessage(INBOX_MESSAGES[0], "INBOX");
  assertEquals(m.uid, 101);
  assertEquals(m.folder, "INBOX");
  assertEquals(m.from, [{
    name: "Alice Example",
    address: "alice@example.com",
  }]);
  assertEquals(m.subject, "Hello there");
  assertEquals(m.date, "2026-01-02T03:04:05.000Z");
  assertEquals(m.messageId, "<msg-101@example.com>");
  assertEquals(m.references, "<root@example.com>");
  assertEquals(m.listId, "Example Discuss <discuss.example.com>");
  assertEquals(m.listUnsubscribe, "<mailto:unsub@example.com>");
  assertEquals(m.listPost, "<mailto:discuss@example.com>");
  assertEquals(m.replyTo, "Example Discuss <discuss@example.com>");
  assertEquals(m.precedence, "list");
  assertEquals(m.flags, ["\\Seen"]);
  assertEquals(m.size, 2048);
  // No body-bearing key exists on the record.
  assertEquals(Object.keys(m).includes("body"), false);
});

Deno.test("normalizeMessage handles string date and Auto-Submitted", () => {
  const m = normalizeMessage(INBOX_MESSAGES[1], "INBOX");
  assertEquals(m.date, "2026-01-03T00:00:00.000Z");
  assertEquals(m.autoSubmitted, "auto-generated");
  assertEquals(m.flags, ["\\Flagged"]);
  assertEquals(m.references, null);
  // Headers absent on this message -> null (not undefined/missing).
  assertEquals(m.listPost, null);
  assertEquals(m.replyTo, null);
});

// ---------------------------------------------------------------------------
// Method tests (through the injected seam)
// ---------------------------------------------------------------------------

Deno.test("listFolders writes a folder tree with counts and totals", async () => {
  const fake = new ScriptedClient({});
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();
  const result = await model.methods.listFolders.execute(
    { _client: factory },
    context,
  );
  assertEquals(result.dataHandles.length, 1);
  assertEquals(writes.length, 1);
  assertEquals(writes[0].spec, "folders");
  assertEquals(writes[0].data.totalFolders, 2);
  assertEquals(writes[0].data.totalMessages, 2);
  const folders = writes[0].data.folders as Array<Record<string, unknown>>;
  assertEquals(folders[0].path, "INBOX");
  assertEquals(folders[0].messages, 2);
  assertEquals(fake.loggedOut, true);
});

Deno.test("folderSlug is collision-free across distinct folder paths", () => {
  // The old `.replace(/[^A-Za-z0-9_.-]+/g, "_")` collapsed both of these to
  // "Team_Alpha"; the bijective slug must keep them distinct.
  assertEquals(folderSlug("Team/Alpha") === folderSlug("Team.Alpha"), false);
  assertEquals(folderSlug("A!!B") === folderSlug("A??B"), false);
  assertEquals(folderSlug("Team.Alpha"), "Team.Alpha");
  assertEquals(folderSlug("Team/Alpha"), "Team%002FAlpha");
  // Distinct inputs -> distinct slugs (injectivity spot-check).
  const inputs = ["INBOX", "A/B", "A.B", "A B", "A_B", "x%y", "unicode-ü"];
  const slugs = new Set(inputs.map(folderSlug));
  assertEquals(slugs.size, inputs.length);
});

Deno.test("sync full scan uses range 1:* when no limit is given", async () => {
  const fake = new ScriptedClient({ INBOX: INBOX_MESSAGES });
  const factory: ClientFactory = () => fake;
  const { context } = makeContext();
  await model.methods.sync.execute({ _client: factory }, context);
  assertEquals(fake.lastRange, "1:*");
});

Deno.test("sync limit computes the most-recent-N range", async () => {
  // INBOX has 2 messages; limit 1 -> start at (2 - 1 + 1) = 2 -> "2:*".
  const fake = new ScriptedClient({ INBOX: INBOX_MESSAGES });
  const factory: ClientFactory = () => fake;
  const { context } = makeContext();
  await model.methods.sync.execute(
    { folder: "INBOX", limit: 1, _client: factory },
    context,
  );
  assertEquals(fake.lastRange, "2:*");
});

/** N minimal synthetic messages (uid 1..N) for range-math coverage. */
function bulkMessages(n: number): FetchMessage[] {
  const out: FetchMessage[] = [];
  for (let i = 1; i <= n; i++) {
    out.push({
      uid: i,
      flags: [],
      size: 100,
      envelope: { subject: `msg ${i}`, date: "2026-01-01T00:00:00.000Z" },
      headers: "",
    });
  }
  return out;
}

Deno.test("sync limit with a larger gap: exists=10, limit=3 -> range 8:*", async () => {
  const fake = new ScriptedClient({ Bulk: bulkMessages(10) });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();
  await model.methods.sync.execute(
    { folder: "Bulk", limit: 3, _client: factory },
    context,
  );
  // (10 - 3 + 1) = 8.
  assertEquals(fake.lastRange, "8:*");
  // The fake returns all 10 regardless of range, but the range string is the
  // contract the real server slices on.
  assertEquals(writes[0].data.folder, "Bulk");
});

Deno.test("sync with limit >= exists falls back to full 1:* scan", async () => {
  // INBOX has 2 messages; limit 5 -> exists > limit is FALSE even though limit
  // is present, so the full-scan branch is taken.
  const fake = new ScriptedClient({ INBOX: INBOX_MESSAGES });
  const factory: ClientFactory = () => fake;
  const { context } = makeContext();
  await model.methods.sync.execute(
    { folder: "INBOX", limit: 5, _client: factory },
    context,
  );
  assertEquals(fake.lastRange, "1:*");
});

Deno.test("sync fetches headers-only and opens mailbox read-only", async () => {
  const fake = new ScriptedClient({ INBOX: INBOX_MESSAGES });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();
  const result = await model.methods.sync.execute(
    { _client: factory },
    context,
  );

  assertEquals(result.dataHandles.length, 1);
  assertEquals(writes[0].spec, "snapshot");
  assertEquals(writes[0].data.folder, "INBOX");
  assertEquals(writes[0].data.count, 2);
  assertEquals(writes[0].data.headersOnly, true);

  // EXAMINE, not SELECT: every open was read-only.
  assertEquals(fake.openedReadOnly, [true]);
  // The fetch asked for envelope + flags + size + the fixed header set, never
  // `source`/`bodyParts` (i.e. no bodies).
  const q = fake.lastFetchQuery as Record<string, unknown>;
  assertEquals(q.envelope, true);
  assertEquals(q.headers, SYNC_HEADERS);
  // SYNC_HEADERS carries the list-classification headers, still header-only.
  assertEquals((q.headers as string[]).includes("list-post"), true);
  assertEquals((q.headers as string[]).includes("reply-to"), true);
  // UID is requested explicitly (a fetch attribute, not a mutation) ...
  assertEquals(q.uid, true);
  assertEquals(Object.keys(q).includes("source"), false);
  assertEquals(Object.keys(q).includes("bodyParts"), false);
  // ... and captured in the snapshot output, including List-Post / Reply-To.
  const msgs = writes[0].data.messages as Array<Record<string, unknown>>;
  assertEquals(msgs[0].uid, 101);
  assertEquals(msgs[1].uid, 102);
  assertEquals(msgs[0].listPost, "<mailto:discuss@example.com>");
  assertEquals(msgs[0].replyTo, "Example Discuss <discuss@example.com>");
  // Message 2 has neither header -> null in the snapshot.
  assertEquals(msgs[1].listPost, null);
  assertEquals(msgs[1].replyTo, null);
  assertEquals(fake.closedCount, 1);
  assertEquals(fake.loggedOut, true);
});

Deno.test("sync fans out over multiple folders in one run", async () => {
  const fake = new ScriptedClient({ INBOX: INBOX_MESSAGES, Archive: [] });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();
  const result = await model.methods.sync.execute(
    { folder: ["INBOX", "Archive"], _client: factory },
    context,
  );
  assertEquals(result.dataHandles.length, 2);
  assertEquals(writes.length, 2);
  assertEquals(writes[1].data.folder, "Archive");
  assertEquals(writes[1].data.count, 0);
  assertEquals(fake.openedReadOnly, [true, true]);
});

Deno.test("defaultClientFactory refuses secure=false without allowInsecure", () => {
  const base = {
    host: "imap.example.com",
    port: 143,
    user: "user@example.net",
    password: "unused",
    secure: false,
    allowInsecure: false,
    defaultFolder: "INBOX",
  };
  // Guard fires before any imapflow construction / network.
  assertThrows(() => defaultClientFactory(base), Error, "secure=false");
});

Deno.test("model exposes the P1 read methods plus the P3 gated-write methods, applyTagPlan, and createFolder, and nothing beyond that scope", () => {
  const names = Object.keys(model.methods).sort();
  assertEquals(names, [
    "addKeywords",
    "applyTagPlan",
    "createFolder",
    "fetchMessage",
    "listFolders",
    "move",
    "removeKeywords",
    "sync",
  ]);
  // copy/expunge/delete are explicitly out of scope for this phase.
  for (const outOfScope of ["copy", "expunge", "delete"]) {
    assertEquals(Object.keys(model.methods).includes(outOfScope), false);
  }
});

Deno.test("every write method defaults dryRun to true in its zod schema", () => {
  for (
    const name of [
      "addKeywords",
      "removeKeywords",
      "move",
      "createFolder",
    ] as const
  ) {
    const schema = model.methods[name].arguments as z.ZodObject<
      { dryRun: z.ZodDefault<z.ZodBoolean> }
    >;
    assertEquals(schema.shape.dryRun.parse(undefined), true);
  }
});

// ---------------------------------------------------------------------------
// Keyword validation (defense-in-depth against the IMAP atom grammar)
// ---------------------------------------------------------------------------

Deno.test("validateKeyword accepts plain custom-keyword atoms", () => {
  validateKeyword("cat/finance");
  validateKeyword("vendor/example-co");
  validateKeyword("flag/has-unsubscribe");
  validateKeyword("list/announce");
});

Deno.test("validateKeyword rejects the system-flag namespace (SEC-2)", () => {
  // These methods set CUSTOM keywords only; any leading backslash (the
  // system/extension flag namespace) is rejected. \\Deleted is the dangerous
  // one -- chained with an implicit expunge it could covertly delete mail.
  assertThrows(() => validateKeyword("\\Deleted"), Error, "system-flag");
  assertThrows(() => validateKeyword("\\Seen"), Error, "system-flag");
  assertThrows(() => validateKeyword("\\Recent"), Error, "system-flag");
  assertThrows(() => validateKeyword("\\Flagged"), Error, "system-flag");
  // A bare backslash is also a leading backslash -> same rejection.
  assertThrows(() => validateKeyword("\\"), Error, "system-flag");
});

Deno.test("validateKeyword rejects non-ASCII code points >= 0x80 (SEC-5)", () => {
  // IMAP atom CHAR is 7-bit US-ASCII; an 8-bit byte is server-dependently
  // mangled. Source stays ASCII via \u escapes.
  assertThrows(() => validateKeyword("caf\u00e9"), Error, "non-ASCII");
  assertThrows(() => validateKeyword("cat/\u00fcber"), Error, "non-ASCII");
  assertThrows(() => validateKeyword("flag/\u{1f4e7}"), Error, "non-ASCII");
  assertThrows(() => validateKeyword("list/\u0080"), Error, "non-ASCII");
  assertThrows(() => validateKeyword("x\u00ff"), Error, "non-ASCII");
});

Deno.test("validateKeyword rejects atom-specials, whitespace, control chars, and interior backslashes", () => {
  assertThrows(() => validateKeyword(""), Error, "empty");
  assertThrows(() => validateKeyword("has space"), Error, "grammar");
  assertThrows(() => validateKeyword('quote"here'), Error, "grammar");
  assertThrows(() => validateKeyword("paren(here)"), Error, "grammar");
  assertThrows(() => validateKeyword("brace{here}"), Error, "grammar");
  assertThrows(() => validateKeyword("percent%here"), Error, "grammar");
  assertThrows(() => validateKeyword("star*here"), Error, "grammar");
  assertThrows(() => validateKeyword("bracket]here"), Error, "grammar");
  assertThrows(() => validateKeyword("a\\b"), Error, "grammar");
  assertThrows(() => validateKeyword("ctrl\x01char"), Error, "grammar");
});

// ---------------------------------------------------------------------------
// uidValidity guard (fails closed)
// ---------------------------------------------------------------------------

Deno.test("checkUidValidity is a no-op when no guard was requested", () => {
  checkUidValidity(undefined, undefined, "INBOX");
  checkUidValidity(555, undefined, "INBOX");
});

Deno.test("checkUidValidity passes when requested matches live", () => {
  checkUidValidity(555, 555, "INBOX");
});

Deno.test("checkUidValidity refuses on mismatch", () => {
  assertThrows(
    () => checkUidValidity(555, 999, "INBOX"),
    Error,
    "stale selection",
  );
});

Deno.test("checkUidValidity fails closed when live is unverifiable", () => {
  assertThrows(
    () => checkUidValidity(undefined, 999, "INBOX"),
    Error,
    "did not report",
  );
});

// ---------------------------------------------------------------------------
// Write-path fixtures: a mutable synthetic client (still no network)
// ---------------------------------------------------------------------------

/** One synthetic message in a {@link ScriptedWriteClient} folder. */
interface WriteFixtureMessage {
  uid: number;
  flags: Set<string>;
}

/**
 * A scripted, mutable client backing the gated write methods. Keeps a
 * per-folder in-memory message store and records every call made to the
 * three mutating members so tests can assert fan-out (one call, not N) and
 * that dryRun=true never reaches them.
 *
 * It faithfully MODELS IMAP CLOSE-implicit-expunge: {@link mailboxClose} drops
 * `\Deleted` messages from the open folder ONLY when that folder was opened
 * read-write (SELECT), exactly as a real server would. A read-only (EXAMINE)
 * close is a no-op. Read-write is reached ONLY through {@link getMailboxLock},
 * whose returned `release()` does NOT expunge. This makes a SEC-1 regression
 * (CLOSE on the read-write path) observable: it would silently delete the
 * `\Deleted` fixture message, failing the test. A healthy write path never
 * calls mailboxClose() while read-write.
 *
 * `partialHonor` (optional): a set of UIDs the mutating members will actually
 * apply; UIDs outside it are silently skipped (modelling a server that drops
 * some of a fan-out set), so tests can assert `discrepancies` is populated.
 */
class ScriptedWriteClient implements ImapClientLike {
  closedCount = 0;
  loggedOut = false;
  openedReadOnly: boolean[] = [];
  lockReleases = 0;
  flagsAddCalls: Array<{ uids: number[]; flags: string[] }> = [];
  flagsRemoveCalls: Array<{ uids: number[]; flags: string[] }> = [];
  moveCalls: Array<{ uids: number[]; destination: string }> = [];
  private openFolder = "";
  private openReadOnly: boolean | null = null;

  /** Count of EXAMINE (mailboxOpen) calls -- drives uidValiditySequence. */
  private examineOpens = 0;

  constructor(
    readonly store: Record<string, WriteFixtureMessage[]>,
    private readonly uidValidity: number | undefined = 555,
    private readonly opts: {
      partialHonor?: Set<number>;
      throwOnMutate?: boolean;
      // When set, getMailboxLock reports THIS uidValidity instead of the
      // Phase-1 (mailboxOpen/EXAMINE) value -- simulates a UIDVALIDITY
      // renumbering between the inspect and the read-write lock phases.
      lockUidValidity?: number;
      // When set, messageFlagsAdd REJECTS for a STORE whose flag set includes
      // this keyword (and succeeds otherwise) -- lets a multi-group
      // applyTagPlan run have an EARLIER group mutate successfully and a LATER
      // group throw, so the NEW-2 partial-evidence path is exercised.
      throwOnKeyword?: string;
      // When set, successive mailboxOpen (EXAMINE) calls report these
      // UIDVALIDITY values in order (falling back to `uidValidity` once
      // exhausted) -- models a mid-group renumbering across chunked fan-outs
      // so ATP-5's cross-chunk uidValidity divergence flag can be asserted.
      uidValiditySequence?: number[];
    } = {},
  ) {}

  private honors(uid: number): boolean {
    return this.opts.partialHonor === undefined ||
      this.opts.partialHonor.has(uid);
  }

  connect(): Promise<void> {
    return Promise.resolve();
  }
  list(): Promise<ListEntry[]> {
    return Promise.resolve([]);
  }
  status(_path: string, _query: StatusQuery): Promise<MailboxStatus> {
    return Promise.resolve({});
  }
  mailboxOpen(
    path: string,
    opts: { readOnly: boolean },
  ): Promise<MailboxOpenResult> {
    this.openFolder = path;
    this.openReadOnly = opts.readOnly;
    this.openedReadOnly.push(opts.readOnly);
    const seq = this.opts.uidValiditySequence;
    const uidValidity = seq
      ? (seq[this.examineOpens] ?? this.uidValidity)
      : this.uidValidity;
    this.examineOpens++;
    return Promise.resolve({
      exists: (this.store[path] ?? []).length,
      uidValidity,
    });
  }
  async *fetch(
    range: string,
    _query: FetchQuery,
  ): AsyncIterable<FetchMessage> {
    const requested = new Set(range.split(",").map((s) => Number(s)));
    for (const m of this.store[this.openFolder] ?? []) {
      if (requested.has(m.uid)) {
        yield await Promise.resolve({ uid: m.uid, flags: m.flags });
      }
    }
  }
  mailboxClose(): Promise<void> {
    this.closedCount++;
    // Model IMAP CLOSE: implicit-expunge \Deleted messages, but ONLY on a
    // read-write (SELECT) mailbox. EXAMINE (read-only) CLOSE never expunges.
    if (this.openReadOnly === false) {
      const cur = this.store[this.openFolder] ?? [];
      this.store[this.openFolder] = cur.filter((m) =>
        !m.flags.has("\\Deleted")
      );
    }
    this.openReadOnly = null;
    return Promise.resolve();
  }
  getMailboxLock(
    path: string,
    opts: { readOnly: boolean },
  ): Promise<MailboxLock> {
    // Mirrors imapflow getMailboxLock: SELECT/EXAMINE the mailbox and return a
    // lock whose release() clears the lock WITHOUT issuing IMAP CLOSE -- so no
    // implicit expunge is ever triggered on the read-write path.
    this.openFolder = path;
    this.openReadOnly = opts.readOnly;
    this.openedReadOnly.push(opts.readOnly);
    return Promise.resolve({
      exists: (this.store[path] ?? []).length,
      uidValidity: this.opts.lockUidValidity ?? this.uidValidity,
      release: () => {
        this.lockReleases++;
        this.openReadOnly = null; // release: NO expunge, unlike mailboxClose()
      },
    });
  }
  logout(): Promise<void> {
    this.loggedOut = true;
    return Promise.resolve();
  }
  messageFlagsAdd(
    uids: number[],
    flags: string[],
    _opts: { uid: true },
  ): Promise<unknown> {
    this.flagsAddCalls.push({ uids, flags });
    if (this.opts.throwOnMutate) {
      return Promise.reject(new Error("synthetic mid-apply failure"));
    }
    if (
      this.opts.throwOnKeyword !== undefined &&
      flags.includes(this.opts.throwOnKeyword)
    ) {
      return Promise.reject(
        new Error(
          `synthetic keyword-group failure: ${this.opts.throwOnKeyword}`,
        ),
      );
    }
    for (const m of this.store[this.openFolder] ?? []) {
      if (uids.includes(m.uid) && this.honors(m.uid)) {
        for (const f of flags) m.flags.add(f);
      }
    }
    return Promise.resolve(true);
  }
  messageFlagsRemove(
    uids: number[],
    flags: string[],
    _opts: { uid: true },
  ): Promise<unknown> {
    this.flagsRemoveCalls.push({ uids, flags });
    if (this.opts.throwOnMutate) {
      return Promise.reject(new Error("synthetic mid-apply failure"));
    }
    for (const m of this.store[this.openFolder] ?? []) {
      if (uids.includes(m.uid) && this.honors(m.uid)) {
        for (const f of flags) m.flags.delete(f);
      }
    }
    return Promise.resolve(true);
  }
  messageMove(
    uids: number[],
    destination: string,
    _opts: { uid: true },
  ): Promise<unknown> {
    this.moveCalls.push({ uids, destination });
    if (this.opts.throwOnMutate) {
      return Promise.reject(new Error("synthetic mid-apply failure"));
    }
    const honored = uids.filter((u) => this.honors(u));
    const source = this.store[this.openFolder] ?? [];
    const moving = source.filter((m) => honored.includes(m.uid));
    this.store[this.openFolder] = source.filter((m) =>
      !honored.includes(m.uid)
    );
    this.store[destination] = [...(this.store[destination] ?? []), ...moving];
    return Promise.resolve({ uidValidity: this.uidValidity });
  }
  mailboxCreate(): Promise<{ path: string; created: boolean }> {
    throw new Error(
      "ScriptedWriteClient (message-write fixture) has no folder-creation " +
        "support",
    );
  }
}

// ---------------------------------------------------------------------------
// addKeywords / removeKeywords / move -- method tests through the injected
// seam. Every fixture is depersonalized: no real mailbox, no network, no
// real vendor/addressee data (plain numeric UIDs and synthetic keywords).
// ---------------------------------------------------------------------------

Deno.test("addKeywords twice: second run's would-affect preview reports new-count 0 (idempotent)", async () => {
  const fake = new ScriptedWriteClient({
    INBOX: [
      { uid: 201, flags: new Set(["\\Seen"]) },
      { uid: 202, flags: new Set() },
    ],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  const run1 = await model.methods.addKeywords.execute(
    {
      folder: "INBOX",
      uids: [201, 202],
      keywords: ["cat/finance"],
      dryRun: false,
      _client: factory,
    },
    context,
  );
  assertEquals(run1.dataHandles.length, 1);
  assertEquals(fake.flagsAddCalls.length, 1);
  assertEquals(fake.flagsAddCalls[0].uids.sort(), [201, 202]);
  assertEquals(writes[0].spec, "applied");
  assertEquals(writes[0].data.applied, 2);

  const run2 = await model.methods.addKeywords.execute(
    {
      folder: "INBOX",
      uids: [201, 202],
      keywords: ["cat/finance"],
      dryRun: true,
      _client: factory,
    },
    context,
  );
  assertEquals(run2.dataHandles.length, 1);
  // No second mutation attempt: still exactly one call from run 1.
  assertEquals(fake.flagsAddCalls.length, 1);
  assertEquals(writes[1].spec, "wouldAffect");
  assertEquals(writes[1].data.count, 0);
  const items = writes[1].data.items as Array<Record<string, unknown>>;
  for (const it of items) {
    assertEquals((it.before as string[]).includes("cat/finance"), true);
    assertEquals((it.after as string[]).includes("cat/finance"), true);
  }
});

Deno.test("addKeywords dryRun=true (default, omitted) performs zero mutation", async () => {
  const fake = new ScriptedWriteClient({
    INBOX: [{ uid: 301, flags: new Set() }],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  const result = await model.methods.addKeywords.execute(
    {
      folder: "INBOX",
      uids: [301],
      keywords: ["cat/finance"],
      // dryRun omitted entirely -- must default to true.
      _client: factory,
    },
    context,
  );

  assertEquals(result.dataHandles.length, 1);
  assertEquals(fake.flagsAddCalls.length, 0);
  assertEquals(writes[0].spec, "wouldAffect");
  assertEquals(writes[0].data.count, 1);

  // Re-read: the fixture's own state is unchanged (no mutation occurred).
  assertEquals(fake.store["INBOX"][0].flags.has("cat/finance"), false);
});

Deno.test("a multi-UID selection issues a SINGLE flag-add command, not N per-message calls", async () => {
  const fake = new ScriptedWriteClient({
    INBOX: [401, 402, 403, 404].map((uid) => ({
      uid,
      flags: new Set<string>(),
    })),
  });
  const factory: ClientFactory = () => fake;
  const { context } = makeContext();

  await model.methods.addKeywords.execute(
    {
      folder: "INBOX",
      uids: [401, 402, 403, 404],
      keywords: ["cat/finance"],
      dryRun: false,
      _client: factory,
    },
    context,
  );

  assertEquals(fake.flagsAddCalls.length, 1);
  assertEquals(fake.flagsAddCalls[0].uids.sort((a, b) => a - b), [
    401,
    402,
    403,
    404,
  ]);
});

Deno.test("a multi-UID move issues a SINGLE move command, not N per-message calls", async () => {
  const fake = new ScriptedWriteClient({
    INBOX: [501, 502, 503].map((uid) => ({ uid, flags: new Set<string>() })),
    Finance: [],
  });
  const factory: ClientFactory = () => fake;
  const { context } = makeContext();

  await model.methods.move.execute(
    {
      folder: "INBOX",
      uids: [501, 502, 503],
      destination: "Finance",
      dryRun: false,
      _client: factory,
    },
    context,
  );

  assertEquals(fake.moveCalls.length, 1);
  assertEquals(fake.moveCalls[0].uids.sort((a, b) => a - b), [501, 502, 503]);
  assertEquals(fake.moveCalls[0].destination, "Finance");
});

Deno.test("removeKeywords of an absent keyword is a no-op (skipped, no call)", async () => {
  const fake = new ScriptedWriteClient({
    INBOX: [{ uid: 601, flags: new Set(["\\Seen"]) }],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  const result = await model.methods.removeKeywords.execute(
    {
      folder: "INBOX",
      uids: [601],
      keywords: ["cat/finance"], // never present on this message
      dryRun: false,
      _client: factory,
    },
    context,
  );

  assertEquals(result.dataHandles.length, 1);
  assertEquals(fake.flagsRemoveCalls.length, 0);
  assertEquals(writes[0].spec, "applied");
  assertEquals(writes[0].data.applied, 0);
  const skipped = writes[0].data.skipped as Array<Record<string, unknown>>;
  assertEquals(skipped.length, 1);
  assertEquals(skipped[0].reason, "keyword(s) already absent");
});

Deno.test("move reports a UID no longer in source under missingFromSource (CORR-1), not success", async () => {
  const fake = new ScriptedWriteClient({
    INBOX: [{ uid: 701, flags: new Set<string>() }],
    Finance: [],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  // First move: actually moves 701 out of INBOX into Finance.
  await model.methods.move.execute(
    {
      folder: "INBOX",
      uids: [701],
      destination: "Finance",
      dryRun: false,
      _client: factory,
    },
    context,
  );
  assertEquals(fake.moveCalls.length, 1);
  assertEquals(writes[0].spec, "applied");
  assertEquals(writes[0].data.applied, 1);
  // Verified move: source re-checked, 701 absent -> no discrepancies.
  assertEquals((writes[0].data.discrepancies as unknown[]).length, 0);
  assertEquals((writes[0].data.missingFromSource as unknown[]).length, 0);

  // Second, identical move: 701 is no longer in INBOX. It is an ANOMALY
  // (expunged or moved elsewhere), reported DISTINCTLY under
  // missingFromSource -- NOT conflated with "already in destination" and NOT
  // counted as skipped/applied. No second move command is issued.
  const run2 = await model.methods.move.execute(
    {
      folder: "INBOX",
      uids: [701],
      destination: "Finance",
      dryRun: false,
      _client: factory,
    },
    context,
  );
  assertEquals(fake.moveCalls.length, 1);
  assertEquals(run2.dataHandles.length, 1);
  assertEquals(writes[1].spec, "applied");
  assertEquals(writes[1].data.applied, 0);
  // skipped is NOT where a vanished UID goes any more.
  assertEquals((writes[1].data.skipped as unknown[]).length, 0);
  const missing = writes[1].data.missingFromSource as Array<
    Record<string, unknown>
  >;
  assertEquals(missing.length, 1);
  assertEquals(missing[0].uid, 701);
  assertEquals(
    String(missing[0].reason).includes("not present in source folder"),
    true,
  );
  // The anomaly reason must NOT claim the message converged in the destination.
  assertEquals(
    String(missing[0].reason).toLowerCase().includes("already in destination"),
    false,
  );
});

Deno.test("move with a mix of present and absent UIDs separates moved from missingFromSource (CORR-1)", async () => {
  const fake = new ScriptedWriteClient({
    // 711 present, 712 absent from source.
    INBOX: [{ uid: 711, flags: new Set<string>() }],
    Finance: [],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  await model.methods.move.execute(
    {
      folder: "INBOX",
      uids: [711, 712],
      destination: "Finance",
      dryRun: true,
      _client: factory,
    },
    context,
  );

  assertEquals(writes[0].spec, "wouldAffect");
  // Only the present UID would move.
  assertEquals(writes[0].data.count, 1);
  const items = writes[0].data.items as Array<Record<string, unknown>>;
  assertEquals(items.length, 1);
  assertEquals(items[0].uid, 711);
  // The absent UID is reported distinctly, not as a would-move item.
  const missing = writes[0].data.missingFromSource as Array<
    Record<string, unknown>
  >;
  assertEquals(missing.length, 1);
  assertEquals(missing[0].uid, 712);
  assertEquals((writes[0].data.skipped as unknown[]).length, 0);
});

Deno.test("uidValidity mismatch refuses with zero mutation and zero data writes", async () => {
  const fake = new ScriptedWriteClient(
    { INBOX: [{ uid: 801, flags: new Set<string>() }] },
    555, // live uidValidity
  );
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  await assertRejects(
    () =>
      model.methods.addKeywords.execute(
        {
          folder: "INBOX",
          uids: [801],
          keywords: ["cat/finance"],
          dryRun: false,
          uidValidity: 999, // stale -- does not match live 555
          _client: factory,
        },
        context,
      ),
    Error,
    "stale selection",
  );

  assertEquals(fake.flagsAddCalls.length, 0);
  assertEquals(writes.length, 0);
});

Deno.test("UIDVALIDITY drift between inspect (EXAMINE) and mutate (lock) is refused (NEW-1)", async () => {
  // Caller supplies NO uidValidity, so the explicit checkUidValidity guard is a
  // no-op; this exercises the two-phase TOCTOU drift check specifically: the
  // EXAMINE phase sees 555, the read-write lock reports 777 (a renumbering).
  const fake = new ScriptedWriteClient(
    { INBOX: [{ uid: 801, flags: new Set<string>() }] },
    555, // Phase-1 (EXAMINE) uidValidity
    { lockUidValidity: 777 }, // Phase-2 (lock) uidValidity -- drifted
  );
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  await assertRejects(
    () =>
      model.methods.addKeywords.execute(
        {
          folder: "INBOX",
          uids: [801],
          keywords: ["cat/finance"],
          dryRun: false,
          // no uidValidity -- the drift check, not checkUidValidity, must catch it
          _client: factory,
        },
        context,
      ),
    Error,
    "UIDVALIDITY changed",
  );

  // Lock was taken (drift is only detectable under the lock) but released in
  // finally, and NO mutation or data write occurred.
  assertEquals(fake.flagsAddCalls.length, 0);
  assertEquals(fake.lockReleases, 1);
  assertEquals(writes.length, 0);
  assertEquals(fake.store.INBOX.length, 1); // store untouched
});

Deno.test("a 0-UID selection returns an explicit empty preview, not a silent no-op", async () => {
  const fake = new ScriptedWriteClient({ INBOX: [] });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  const result = await model.methods.addKeywords.execute(
    {
      folder: "INBOX",
      uids: [],
      keywords: ["cat/finance"],
      _client: factory,
    },
    context,
  );

  assertEquals(result.dataHandles.length, 1);
  assertEquals(fake.flagsAddCalls.length, 0);
  assertEquals(writes[0].spec, "wouldAffect");
  assertEquals(writes[0].data.count, 0);
  assertEquals(writes[0].data.requestedCount, 0);
  assertEquals((writes[0].data.items as unknown[]).length, 0);
});

Deno.test("dryRun preview opens the mailbox READ-ONLY (EXAMINE), never read-write (SEC-1)", async () => {
  const fake = new ScriptedWriteClient({
    INBOX: [{ uid: 901, flags: new Set<string>() }],
  });
  const factory: ClientFactory = () => fake;
  const { context } = makeContext();

  await model.methods.addKeywords.execute(
    {
      folder: "INBOX",
      uids: [901],
      keywords: ["cat/finance"],
      dryRun: true,
      _client: factory,
    },
    context,
  );

  // Preview only inspects: EXAMINE (read-only), closed once, no lock acquired.
  assertEquals(fake.openedReadOnly, [true]);
  assertEquals(fake.closedCount, 1);
  assertEquals(fake.lockReleases, 0);
  assertEquals(fake.loggedOut, true);
});

Deno.test("mutate path opens read-write via a LOCK and releases it WITHOUT a CLOSE (SEC-1)", async () => {
  const fake = new ScriptedWriteClient({
    INBOX: [{ uid: 902, flags: new Set<string>() }],
  });
  const factory: ClientFactory = () => fake;
  const { context } = makeContext();

  await model.methods.addKeywords.execute(
    {
      folder: "INBOX",
      uids: [902],
      keywords: ["cat/finance"],
      dryRun: false,
      _client: factory,
    },
    context,
  );

  // Phase 1 EXAMINE (read-only) then Phase 2 read-write lock.
  assertEquals(fake.openedReadOnly, [true, false]);
  // Exactly ONE close (the EXAMINE); the read-write box is released, not
  // closed -- a CLOSE on the read-write box would implicit-expunge.
  assertEquals(fake.closedCount, 1);
  assertEquals(fake.lockReleases, 1);
});

Deno.test("dryRun=true leaves a pre-existing \\Deleted message intact (SEC-1: no implicit expunge)", async () => {
  // A message another session flagged \Deleted sits in the folder. A no-op
  // preview must NOT trigger CLOSE (and thus must not expunge it). The fake
  // models CLOSE-implicit-expunge on a read-write box, so a regression that
  // opened read-write + closed on the preview path would delete uid 1001 and
  // fail this test.
  const fake = new ScriptedWriteClient({
    INBOX: [
      { uid: 1001, flags: new Set(["\\Deleted"]) },
      { uid: 1002, flags: new Set<string>() },
    ],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  await model.methods.addKeywords.execute(
    {
      folder: "INBOX",
      uids: [1002],
      keywords: ["cat/finance"],
      dryRun: true,
      _client: factory,
    },
    context,
  );

  assertEquals(writes[0].spec, "wouldAffect");
  // The \Deleted message survives the preview untouched.
  assertEquals(fake.store["INBOX"].some((m) => m.uid === 1001), true);
  assertEquals(fake.store["INBOX"].length, 2);
  assertEquals(fake.openedReadOnly, [true]);
});

Deno.test("mutate path leaves an untargeted \\Deleted message intact (SEC-1: release != CLOSE)", async () => {
  // uid 1101 is \Deleted (set by another session) and is NOT in our UID set.
  // Our dryRun=false add targets only 1102. Because the read-write box is
  // released (never CLOSEd), 1101 must survive. A regression to mailboxClose()
  // on the read-write box would expunge it.
  const fake = new ScriptedWriteClient({
    INBOX: [
      { uid: 1101, flags: new Set(["\\Deleted"]) },
      { uid: 1102, flags: new Set<string>() },
    ],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  await model.methods.addKeywords.execute(
    {
      folder: "INBOX",
      uids: [1102],
      keywords: ["cat/finance"],
      dryRun: false,
      _client: factory,
    },
    context,
  );

  assertEquals(writes[0].spec, "applied");
  assertEquals(writes[0].data.applied, 1);
  assertEquals(fake.store["INBOX"].some((m) => m.uid === 1101), true);
  assertEquals(fake.lockReleases, 1);
  assertEquals(fake.closedCount, 1); // only the EXAMINE close
});

Deno.test("addKeywords rejects the system-flag namespace before any connection (SEC-2)", async () => {
  const fake = new ScriptedWriteClient({
    INBOX: [{ uid: 1201, flags: new Set<string>() }],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  for (const bad of ["\\Deleted", "\\Seen"]) {
    await assertRejects(
      () =>
        model.methods.addKeywords.execute(
          {
            folder: "INBOX",
            uids: [1201],
            keywords: [bad],
            dryRun: false,
            _client: factory,
          },
          context,
        ),
      Error,
      "system-flag",
    );
  }
  // Rejected before any open/mutate/write.
  assertEquals(fake.openedReadOnly.length, 0);
  assertEquals(fake.flagsAddCalls.length, 0);
  assertEquals(writes.length, 0);
});

Deno.test("write methods reject an over-cap UID set with a batching hint (SEC-3)", async () => {
  const fake = new ScriptedWriteClient({ INBOX: [] });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  // MAX_UIDS + 1 distinct UIDs.
  const tooMany = Array.from({ length: MAX_UIDS + 1 }, (_, i) => i + 1);

  await assertRejects(
    () =>
      model.methods.addKeywords.execute(
        {
          folder: "INBOX",
          uids: tooMany,
          keywords: ["cat/finance"],
          dryRun: true,
          _client: factory,
        },
        context,
      ),
    Error,
    "Batch",
  );
  // Exactly MAX_UIDS is accepted (boundary): opens for inspection, no throw.
  const atCap = Array.from({ length: MAX_UIDS }, (_, i) => i + 1);
  await model.methods.addKeywords.execute(
    {
      folder: "INBOX",
      uids: atCap,
      keywords: ["cat/finance"],
      dryRun: true,
      _client: factory,
    },
    context,
  );
  // The over-cap call wrote nothing; the at-cap call wrote one preview.
  assertEquals(writes.length, 1);
  assertEquals(writes[0].spec, "wouldAffect");
});

Deno.test("keywords are de-duplicated before diff/record (CORR-7)", async () => {
  const fake = new ScriptedWriteClient({
    INBOX: [{ uid: 1301, flags: new Set<string>() }],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  await model.methods.addKeywords.execute(
    {
      folder: "INBOX",
      uids: [1301],
      keywords: ["cat/finance", "cat/finance", "cat/finance"],
      dryRun: true,
      _client: factory,
    },
    context,
  );

  const items = writes[0].data.items as Array<Record<string, unknown>>;
  // An IMAP flag set cannot hold a dup token -> after has it exactly once.
  const after = items[0].after as string[];
  assertEquals(after.filter((f) => f === "cat/finance").length, 1);
});

Deno.test("custom keywords are case-sensitive: 'cat/Finance' and 'cat/finance' are DISTINCT (CORR-2)", async () => {
  // With system flags rejected (SEC-2), only custom keywords remain, and the
  // IMAP keyword grammar is case-sensitive. A request for 'cat/finance' over
  // an existing 'cat/Finance' is a real change, not a no-op.
  const fake = new ScriptedWriteClient({
    INBOX: [{ uid: 1401, flags: new Set(["cat/Finance"]) }],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  await model.methods.addKeywords.execute(
    {
      folder: "INBOX",
      uids: [1401],
      keywords: ["cat/finance"],
      dryRun: true,
      _client: factory,
    },
    context,
  );

  // 'cat/finance' is treated as new (distinct from 'cat/Finance').
  assertEquals(writes[0].data.count, 1);
  const items = writes[0].data.items as Array<Record<string, unknown>>;
  const after = items[0].after as string[];
  assertEquals(after.includes("cat/Finance"), true);
  assertEquals(after.includes("cat/finance"), true);
});

Deno.test("addKeywords dryRun=false twice is idempotent: 2nd real run mutates nothing (CORR-6)", async () => {
  const fake = new ScriptedWriteClient({
    INBOX: [
      { uid: 1501, flags: new Set<string>() },
      { uid: 1502, flags: new Set<string>() },
    ],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  const args = {
    folder: "INBOX",
    uids: [1501, 1502],
    keywords: ["cat/finance"],
    dryRun: false,
    _client: factory,
  };
  await model.methods.addKeywords.execute(args, context);
  assertEquals(fake.flagsAddCalls.length, 1);
  assertEquals(writes[0].data.applied, 2);

  // Second REAL run (dryRun=false): keyword already present on both -> nothing
  // to change -> no second STORE command, applied 0, no read-write lock.
  await model.methods.addKeywords.execute(args, context);
  assertEquals(fake.flagsAddCalls.length, 1);
  assertEquals(writes[1].spec, "applied");
  assertEquals(writes[1].data.applied, 0);
  assertEquals((writes[1].data.skipped as unknown[]).length, 2);
  // Second run never opened read-write (changedUids was empty).
  assertEquals(fake.lockReleases, 1);
});

Deno.test("removeKeywords dryRun=false twice is idempotent: 2nd real run mutates nothing (CORR-6)", async () => {
  const fake = new ScriptedWriteClient({
    INBOX: [
      { uid: 1601, flags: new Set(["cat/finance"]) },
      { uid: 1602, flags: new Set(["cat/finance"]) },
    ],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  const args = {
    folder: "INBOX",
    uids: [1601, 1602],
    keywords: ["cat/finance"],
    dryRun: false,
    _client: factory,
  };
  await model.methods.removeKeywords.execute(args, context);
  assertEquals(fake.flagsRemoveCalls.length, 1);
  assertEquals(writes[0].data.applied, 2);

  // Second REAL run: keyword already absent -> nothing to change.
  await model.methods.removeKeywords.execute(args, context);
  assertEquals(fake.flagsRemoveCalls.length, 1);
  assertEquals(writes[1].spec, "applied");
  assertEquals(writes[1].data.applied, 0);
  assertEquals((writes[1].data.skipped as unknown[]).length, 2);
  assertEquals(fake.lockReleases, 1);
});

Deno.test("applied evidence is VERIFIED: partial server honor populates discrepancies (CORR-3, addKeywords)", async () => {
  // The server honors only 1701; it silently drops 1702 from the fan-out set.
  const fake = new ScriptedWriteClient(
    {
      INBOX: [
        { uid: 1701, flags: new Set<string>() },
        { uid: 1702, flags: new Set<string>() },
      ],
    },
    555,
    { partialHonor: new Set([1701]) },
  );
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  await model.methods.addKeywords.execute(
    {
      folder: "INBOX",
      uids: [1701, 1702],
      keywords: ["cat/finance"],
      dryRun: false,
      _client: factory,
    },
    context,
  );

  assertEquals(writes[0].spec, "applied");
  // Only one UID actually reached the expected state.
  assertEquals(writes[0].data.applied, 1);
  const discrepancies = writes[0].data.discrepancies as Array<
    Record<string, unknown>
  >;
  assertEquals(discrepancies.length, 1);
  assertEquals(discrepancies[0].uid, 1702);
  // items reflect REALITY (re-fetched), not the prediction.
  const items = writes[0].data.items as Array<Record<string, unknown>>;
  const it1702 = items.find((it) => it.uid === 1702)!;
  assertEquals((it1702.after as string[]).includes("cat/finance"), false);
  const it1701 = items.find((it) => it.uid === 1701)!;
  assertEquals((it1701.after as string[]).includes("cat/finance"), true);
});

Deno.test("applied evidence is VERIFIED: partial server honor populates discrepancies (CORR-3, move)", async () => {
  // The server moves 1801 but silently leaves 1802 in the source.
  const fake = new ScriptedWriteClient(
    {
      INBOX: [
        { uid: 1801, flags: new Set<string>() },
        { uid: 1802, flags: new Set<string>() },
      ],
      Finance: [],
    },
    555,
    { partialHonor: new Set([1801]) },
  );
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  await model.methods.move.execute(
    {
      folder: "INBOX",
      uids: [1801, 1802],
      destination: "Finance",
      dryRun: false,
      _client: factory,
    },
    context,
  );

  assertEquals(writes[0].spec, "applied");
  // One of the two UIDs actually left the source.
  assertEquals(writes[0].data.applied, 1);
  const discrepancies = writes[0].data.discrepancies as Array<
    Record<string, unknown>
  >;
  assertEquals(discrepancies.length, 1);
  assertEquals(discrepancies[0].uid, 1802);
  // 1802 is still in the source folder (not moved).
  assertEquals(fake.store["INBOX"].some((m) => m.uid === 1802), true);
});

Deno.test("a mutation that throws mid-apply records partial/error evidence before propagating (CORR-4)", async () => {
  const fake = new ScriptedWriteClient(
    { INBOX: [{ uid: 1901, flags: new Set<string>() }] },
    555,
    { throwOnMutate: true },
  );
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  await assertRejects(
    () =>
      model.methods.addKeywords.execute(
        {
          folder: "INBOX",
          uids: [1901],
          keywords: ["cat/finance"],
          dryRun: false,
          _client: factory,
        },
        context,
      ),
    Error,
    "synthetic mid-apply failure",
  );

  // Evidence was captured BEFORE the exception propagated.
  assertEquals(writes.length, 1);
  assertEquals(writes[0].spec, "applied");
  assertEquals(typeof writes[0].data.error, "string");
  assertEquals(
    String(writes[0].data.error).includes("synthetic mid-apply failure"),
    true,
  );
  const discrepancies = writes[0].data.discrepancies as Array<
    Record<string, unknown>
  >;
  assertEquals(discrepancies.length, 1);
  assertEquals(discrepancies[0].uid, 1901);
  // The command was transmitted (attempt recorded), and the lock was released.
  assertEquals(fake.flagsAddCalls.length, 1);
  assertEquals(fake.lockReleases, 1);
});

Deno.test("move rejects a self-move (destination === folder) with no connection (CORR-5)", async () => {
  const fake = new ScriptedWriteClient({
    INBOX: [{ uid: 2001, flags: new Set<string>() }],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  await assertRejects(
    () =>
      model.methods.move.execute(
        {
          folder: "INBOX",
          uids: [2001],
          destination: "INBOX",
          dryRun: false,
          _client: factory,
        },
        context,
      ),
    Error,
    "must differ from the source",
  );
  assertEquals(fake.openedReadOnly.length, 0);
  assertEquals(fake.moveCalls.length, 0);
  assertEquals(writes.length, 0);
});

// ---------------------------------------------------------------------------
// applyTagPlan -- Reconcile-B. Every test injects its tagPlan via the `_plan`
// seam (never readModelData) and a ScriptedWriteClient (never a live
// mailbox). Fixtures are depersonalized: plain numeric UIDs, synthetic
// folder/keyword names.
// ---------------------------------------------------------------------------

/** One synthetic tagPlan entry, matching @shrug/mail-ontology's shape. */
interface TagPlanFixtureItem {
  folder: string;
  uid: number;
  keywords: string[];
  financeMove: string | null;
}

Deno.test("applyTagPlan groups by (folder,keyword) and (folder,destination): ONE STORE per keyword group, ONE move per destination group", async () => {
  const fake = new ScriptedWriteClient({
    INBOX: [
      { uid: 1, flags: new Set<string>() },
      { uid: 2, flags: new Set<string>() },
      { uid: 3, flags: new Set<string>() },
    ],
    Finance: [],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  const plan: TagPlanFixtureItem[] = [
    {
      folder: "INBOX",
      uid: 1,
      keywords: ["cat/finance"],
      financeMove: "Finance",
    },
    {
      folder: "INBOX",
      uid: 2,
      keywords: ["cat/finance"],
      financeMove: "Finance",
    },
    { folder: "INBOX", uid: 3, keywords: ["cat/other"], financeMove: null },
  ];

  await model.methods.applyTagPlan.execute(
    {
      ontologyModel: "ontology-test",
      dryRun: false,
      _plan: plan,
      _client: factory,
    },
    context,
  );

  // ONE STORE per (folder,keyword) group, each over ALL its UIDs -- never a
  // per-message loop.
  assertEquals(fake.flagsAddCalls.length, 2);
  const financeCall = fake.flagsAddCalls.find((c) =>
    c.flags.includes("cat/finance")
  )!;
  assertEquals(financeCall.uids.sort((a, b) => a - b), [1, 2]);
  const otherCall = fake.flagsAddCalls.find((c) =>
    c.flags.includes("cat/other")
  )!;
  assertEquals(otherCall.uids, [3]);

  // ONE move per (folder,destination) group, over all its UIDs.
  assertEquals(fake.moveCalls.length, 1);
  assertEquals(fake.moveCalls[0].destination, "Finance");
  assertEquals(fake.moveCalls[0].uids.sort((a, b) => a - b), [1, 2]);

  assertEquals(writes.length, 1);
  assertEquals(writes[0].spec, "tagPlanApplied");
  const data = writes[0].data as {
    keywordGroups: Array<Record<string, unknown>>;
    moveGroups: Array<Record<string, unknown>>;
    totals: Record<string, number>;
  };
  assertEquals(data.keywordGroups.length, 2);
  assertEquals(data.moveGroups.length, 1);
  assertEquals(data.totals.added, 3); // 2 (finance) + 1 (other)
  assertEquals(data.totals.moved, 2);
});

Deno.test("applyTagPlan dryRun=true (default) performs zero mutation", async () => {
  const fake = new ScriptedWriteClient({
    INBOX: [
      { uid: 11, flags: new Set<string>() },
      { uid: 12, flags: new Set<string>() },
    ],
    Finance: [],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  const plan: TagPlanFixtureItem[] = [
    {
      folder: "INBOX",
      uid: 11,
      keywords: ["cat/finance"],
      financeMove: "Finance",
    },
    {
      folder: "INBOX",
      uid: 12,
      keywords: ["cat/finance"],
      financeMove: "Finance",
    },
  ];

  await model.methods.applyTagPlan.execute(
    { ontologyModel: "ontology-test", _plan: plan, _client: factory },
    context,
  );

  assertEquals(fake.flagsAddCalls.length, 0);
  assertEquals(fake.moveCalls.length, 0);
  assertEquals(fake.lockReleases, 0);
  assertEquals(writes[0].spec, "tagPlanPreview");
  const data = writes[0].data as {
    keywordGroups: Array<{ addCount: number; alreadyPresentCount: number }>;
    moveGroups: Array<{ missingFromSource: number; uidCount: number }>;
    totals: Record<string, number>;
  };
  assertEquals(data.keywordGroups[0].addCount, 2);
  assertEquals(data.keywordGroups[0].alreadyPresentCount, 0);
  assertEquals(data.moveGroups[0].missingFromSource, 0);
  assertEquals(data.totals.added, 2);
  assertEquals(data.totals.moved, 2);
});

Deno.test("applyTagPlan is idempotent: a 2nd real run over an already-tagged, already-moved mailbox shows 0 new", async () => {
  const fake = new ScriptedWriteClient({
    INBOX: [{ uid: 21, flags: new Set<string>() }],
    Finance: [],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  const plan: TagPlanFixtureItem[] = [
    {
      folder: "INBOX",
      uid: 21,
      keywords: ["cat/finance"],
      financeMove: "Finance",
    },
  ];
  const args = {
    ontologyModel: "ontology-test",
    dryRun: false,
    _plan: plan,
    _client: factory,
  };

  await model.methods.applyTagPlan.execute(args, context);
  assertEquals(fake.flagsAddCalls.length, 1);
  assertEquals(fake.moveCalls.length, 1);
  const first = writes[0].data as {
    totals: Record<string, number>;
  };
  assertEquals(first.totals.added, 1);
  assertEquals(first.totals.moved, 1);

  // Second real run: 21 has already moved OUT of INBOX (to Finance) -- so
  // the keyword group's (folder=INBOX, uid=21) lookup finds nothing there
  // anymore (silently absorbed into the uid-not-found gap, same as
  // addKeywords' own "uid not found in folder" skip; neither added nor
  // already-present), and the move group reports 21 as missingFromSource
  // (already moved -- an anomaly to review, never silently re-conflated with
  // success). No new STORE/MOVE commands are issued either way.
  await model.methods.applyTagPlan.execute(args, context);
  assertEquals(fake.flagsAddCalls.length, 1);
  assertEquals(fake.moveCalls.length, 1);
  const second = writes[1].data as {
    keywordGroups: Array<
      { uidCount: number; appliedCount: number; alreadyPresentCount: number }
    >;
    moveGroups: Array<{ appliedCount: number; missingFromSource: number }>;
    totals: Record<string, number>;
  };
  assertEquals(second.keywordGroups[0].uidCount, 1);
  assertEquals(second.keywordGroups[0].appliedCount, 0);
  assertEquals(second.keywordGroups[0].alreadyPresentCount, 0);
  assertEquals(second.moveGroups[0].appliedCount, 0);
  assertEquals(second.moveGroups[0].missingFromSource, 1);
  assertEquals(second.totals.added, 0);
  assertEquals(second.totals.moved, 0);
  assertEquals(second.totals.missingFromSource, 1);
});

Deno.test("applyTagPlan aggregates a Finance move group with a mix of present and already-moved UIDs (missingFromSource)", async () => {
  // 31 is still in INBOX; 32 has already moved to Finance by another run.
  const fake = new ScriptedWriteClient({
    INBOX: [{ uid: 31, flags: new Set<string>() }],
    Finance: [{ uid: 32, flags: new Set<string>() }],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  const plan: TagPlanFixtureItem[] = [
    { folder: "INBOX", uid: 31, keywords: [], financeMove: "Finance" },
    { folder: "INBOX", uid: 32, keywords: [], financeMove: "Finance" },
  ];

  await model.methods.applyTagPlan.execute(
    {
      ontologyModel: "ontology-test",
      dryRun: false,
      _plan: plan,
      _client: factory,
    },
    context,
  );

  assertEquals(fake.moveCalls.length, 1);
  assertEquals(fake.moveCalls[0].uids, [31]); // only the present UID is moved
  const data = writes[0].data as {
    moveGroups: Array<
      { uidCount: number; appliedCount: number; missingFromSource: number }
    >;
    totals: Record<string, number>;
  };
  assertEquals(data.moveGroups.length, 1);
  assertEquals(data.moveGroups[0].uidCount, 2);
  assertEquals(data.moveGroups[0].appliedCount, 1);
  assertEquals(data.moveGroups[0].missingFromSource, 1);
  assertEquals(data.totals.missingFromSource, 1);
});

Deno.test("applyTagPlan chunks a (folder,keyword) group over MAX_UIDS into multiple fan-out STOREs", async () => {
  const n = MAX_UIDS + 10;
  const store: Record<string, { uid: number; flags: Set<string> }[]> = {
    INBOX: Array.from({ length: n }, (_, i) => ({
      uid: i + 1,
      flags: new Set<string>(),
    })),
  };
  const fake = new ScriptedWriteClient(store);
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  const plan: TagPlanFixtureItem[] = Array.from({ length: n }, (_, i) => ({
    folder: "INBOX",
    uid: i + 1,
    keywords: ["cat/finance"],
    financeMove: null,
  }));

  await model.methods.applyTagPlan.execute(
    {
      ontologyModel: "ontology-test",
      dryRun: false,
      _plan: plan,
      _client: factory,
    },
    context,
  );

  // Over the MAX_UIDS cap -- chunked into 2 fan-out STOREs, never rejected.
  assertEquals(fake.flagsAddCalls.length, 2);
  assertEquals(fake.flagsAddCalls[0].uids.length, MAX_UIDS);
  assertEquals(fake.flagsAddCalls[1].uids.length, 10);
  // ONE logical row in the output per (folder,keyword) group, regardless of
  // how many chunks it took -- aggregated across both.
  const data = writes[0].data as {
    keywordGroups: Array<{ uidCount: number; appliedCount: number }>;
  };
  assertEquals(data.keywordGroups.length, 1);
  assertEquals(data.keywordGroups[0].uidCount, n);
  assertEquals(data.keywordGroups[0].appliedCount, n);
});

Deno.test("applyTagPlan aborts the whole run on an invalid tagPlan keyword, before any connection (trust-but-verify)", async () => {
  const fake = new ScriptedWriteClient({
    INBOX: [{ uid: 41, flags: new Set<string>() }],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  const plan: TagPlanFixtureItem[] = [
    { folder: "INBOX", uid: 41, keywords: ["\\Deleted"], financeMove: null },
  ];

  await assertRejects(
    () =>
      model.methods.applyTagPlan.execute(
        {
          ontologyModel: "ontology-test",
          dryRun: false,
          _plan: plan,
          _client: factory,
        },
        context,
      ),
    Error,
    "system-flag",
  );

  assertEquals(fake.openedReadOnly.length, 0);
  assertEquals(fake.flagsAddCalls.length, 0);
  assertEquals(writes.length, 0);
});

Deno.test("applyTagPlan applyMoves=false skips Finance moves entirely", async () => {
  const fake = new ScriptedWriteClient({
    INBOX: [{ uid: 51, flags: new Set<string>() }],
    Finance: [],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  const plan: TagPlanFixtureItem[] = [
    {
      folder: "INBOX",
      uid: 51,
      keywords: ["cat/finance"],
      financeMove: "Finance",
    },
  ];

  await model.methods.applyTagPlan.execute(
    {
      ontologyModel: "ontology-test",
      dryRun: false,
      applyMoves: false,
      _plan: plan,
      _client: factory,
    },
    context,
  );

  assertEquals(fake.moveCalls.length, 0);
  assertEquals(fake.flagsAddCalls.length, 1);
  const data = writes[0].data as { moveGroups: unknown[] };
  assertEquals(data.moveGroups.length, 0);
});

Deno.test("applyTagPlan over a 0-item plan writes an explicit empty preview, not a silent no-op, with no connection", async () => {
  const fake = new ScriptedWriteClient({});
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  const result = await model.methods.applyTagPlan.execute(
    { ontologyModel: "ontology-test", _plan: [], _client: factory },
    context,
  );

  assertEquals(result.dataHandles.length, 1);
  assertEquals(fake.openedReadOnly.length, 0);
  assertEquals(writes[0].spec, "tagPlanPreview");
  const data = writes[0].data as {
    keywordGroups: unknown[];
    moveGroups: unknown[];
    totals: Record<string, number>;
  };
  assertEquals(data.keywordGroups.length, 0);
  assertEquals(data.moveGroups.length, 0);
  assertEquals(data.totals.added, 0);
  assertEquals(data.totals.moved, 0);
});

// ---------------------------------------------------------------------------
// applyTagPlan -- adversarial-review follow-ups (NEW-2, ATP-1..5)
// ---------------------------------------------------------------------------

Deno.test("applyTagPlan NEW-2: a group that throws mid-run persists PARTIAL tagPlanApplied evidence (completed groups + error) before propagating", async () => {
  // Two keyword groups. The first (cat/finance) mutates successfully; the
  // second (cat/boom) rejects at the STORE. A throw must NOT lose the audit
  // for the group that already changed live mail: a partial tagPlanApplied
  // with the completed group + the error message is persisted, THEN rethrown.
  const fake = new ScriptedWriteClient(
    {
      INBOX: [
        { uid: 1, flags: new Set<string>() },
        { uid: 2, flags: new Set<string>() },
      ],
    },
    555,
    { throwOnKeyword: "cat/boom" },
  );
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  const plan: TagPlanItem[] = [
    { folder: "INBOX", uid: 1, keywords: ["cat/finance"], financeMove: null },
    { folder: "INBOX", uid: 2, keywords: ["cat/boom"], financeMove: null },
  ];

  await assertRejects(
    () =>
      model.methods.applyTagPlan.execute(
        {
          ontologyModel: "ontology-test",
          dryRun: false,
          _plan: plan,
          _client: factory,
        },
        context,
      ),
    Error,
    "synthetic keyword-group failure",
  );

  // Partial evidence WAS written before the throw propagated.
  assertEquals(writes.length, 1);
  assertEquals(writes[0].spec, "tagPlanApplied");
  const data = writes[0].data as {
    error?: string;
    keywordGroups: Array<{ keyword: string; appliedCount: number }>;
    totals: Record<string, number>;
  };
  assertEquals(typeof data.error, "string");
  assertEquals(String(data.error).includes("synthetic keyword-group"), true);
  // Only the group that completed before the throw is recorded (cat/finance).
  assertEquals(data.keywordGroups.length, 1);
  assertEquals(data.keywordGroups[0].keyword, "cat/finance");
  assertEquals(data.keywordGroups[0].appliedCount, 1);
  assertEquals(data.totals.added, 1);
  // The successful group's STORE really did land on uid 1.
  assertEquals(fake.store["INBOX"][0].flags.has("cat/finance"), true);
});

Deno.test("applyTagPlan ATP-1: a keyword-group UID absent from its folder is reported as notFound, not silently absorbed", async () => {
  // uid 1 is in INBOX; uid 2 is named by the plan but NOT present in INBOX.
  const fake = new ScriptedWriteClient({
    INBOX: [{ uid: 1, flags: new Set<string>() }],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  const plan: TagPlanItem[] = [
    { folder: "INBOX", uid: 1, keywords: ["cat/finance"], financeMove: null },
    { folder: "INBOX", uid: 2, keywords: ["cat/finance"], financeMove: null },
  ];

  await model.methods.applyTagPlan.execute(
    { ontologyModel: "ontology-test", _plan: plan, _client: factory },
    context,
  );

  assertEquals(writes[0].spec, "tagPlanPreview");
  const data = writes[0].data as {
    keywordGroups: Array<
      { uidCount: number; addCount: number; notFound: number }
    >;
    totals: Record<string, number>;
  };
  assertEquals(data.keywordGroups.length, 1);
  assertEquals(data.keywordGroups[0].uidCount, 2);
  assertEquals(data.keywordGroups[0].addCount, 1); // only the present UID
  assertEquals(data.keywordGroups[0].notFound, 1); // the vanished UID, surfaced
  assertEquals(data.totals.notFound, 1);
});

Deno.test("toTagPlanItems (ATP-2): decodes valid entries and counts malformed drops", () => {
  const rec: DataRecord = {
    name: "tagPlan",
    specName: "tagPlan",
    attributes: {
      items: [
        {
          folder: "INBOX",
          uid: 1,
          keywords: ["cat/finance"],
          financeMove: "Finance",
        },
        { folder: "INBOX", uid: 2, keywords: [], financeMove: null },
        // malformed: missing folder
        { uid: 3, keywords: ["x"], financeMove: null },
        // malformed: non-numeric uid
        { folder: "INBOX", uid: "nope", keywords: [], financeMove: null },
        // malformed: empty folder
        { folder: "", uid: 4, keywords: [], financeMove: null },
        // malformed: not an object
        42,
      ],
    },
  };
  const { items, droppedCount } = toTagPlanItems(rec);
  assertEquals(items.length, 2);
  assertEquals(items[0], {
    folder: "INBOX",
    uid: 1,
    keywords: ["cat/finance"],
    financeMove: "Finance",
  });
  assertEquals(droppedCount, 4);
});

Deno.test("toTagPlanItems (ATP-2): absent/empty record yields empty items, zero drops", () => {
  assertEquals(toTagPlanItems(undefined), { items: [], droppedCount: 0 });
  assertEquals(toTagPlanItems({ name: "tagPlan" }), {
    items: [],
    droppedCount: 0,
  });
  assertEquals(
    toTagPlanItems({ name: "tagPlan", attributes: { items: "not-array" } }),
    { items: [], droppedCount: 0 },
  );
});

Deno.test("applyTagPlan ATP-2: the live readModelData path decodes the latest tagPlan and surfaces droppedCount", async () => {
  // Exercises the PRODUCTION path (no _plan seam): a context whose
  // readModelData returns two tagPlan versions (latest wins) with one
  // malformed entry that must be dropped and counted.
  const fake = new ScriptedWriteClient({
    INBOX: [{ uid: 1, flags: new Set<string>() }],
  });
  const factory: ClientFactory = () => fake;
  const writes: Array<
    { spec: string; name: string; data: Record<string, unknown> }
  > = [];
  const context = {
    globalArgs: {
      host: "imap.example.com",
      port: 993,
      user: "user@example.net",
      password: "unused-in-tests",
      secure: true,
      allowInsecure: false,
      defaultFolder: "INBOX",
    },
    logger: { info() {}, warning() {} },
    readModelData: (_model: string, spec?: string): Promise<DataRecord[]> =>
      Promise.resolve(
        spec === "tagPlan"
          ? [
            // older version (ignored -- only the LATEST is applied)
            { name: "tagPlan", attributes: { items: [] } },
            {
              name: "tagPlan",
              attributes: {
                items: [
                  {
                    folder: "INBOX",
                    uid: 1,
                    keywords: ["cat/finance"],
                    financeMove: null,
                  },
                  // malformed -> dropped + counted
                  { uid: 99, keywords: [], financeMove: null },
                ],
              },
            },
          ]
          : [],
      ),
    writeResource: (
      spec: string,
      name: string,
      data: Record<string, unknown>,
    ) => {
      writes.push({ spec, name, data });
      return Promise.resolve({ name });
    },
  };

  await model.methods.applyTagPlan.execute(
    { ontologyModel: "ontology-test", _client: factory },
    context,
  );

  assertEquals(writes[0].spec, "tagPlanPreview");
  const data = writes[0].data as {
    droppedCount: number;
    keywordGroups: Array<{ keyword: string; addCount: number }>;
  };
  // The latest version's one valid entry was applied; the malformed one was
  // dropped and surfaced -- not silent.
  assertEquals(data.droppedCount, 1);
  assertEquals(data.keywordGroups.length, 1);
  assertEquals(data.keywordGroups[0].keyword, "cat/finance");
  assertEquals(data.keywordGroups[0].addCount, 1);
});

Deno.test("applyTagPlan ATP-3: a self-move (financeMove === folder) aborts before any connection", async () => {
  const fake = new ScriptedWriteClient({
    INBOX: [{ uid: 1, flags: new Set<string>() }],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  const plan: TagPlanItem[] = [
    { folder: "INBOX", uid: 1, keywords: [], financeMove: "INBOX" },
  ];

  await assertRejects(
    () =>
      model.methods.applyTagPlan.execute(
        {
          ontologyModel: "ontology-test",
          dryRun: false,
          _plan: plan,
          _client: factory,
        },
        context,
      ),
    Error,
    "move within a single folder",
  );

  assertEquals(fake.openedReadOnly.length, 0);
  assertEquals(fake.moveCalls.length, 0);
  assertEquals(writes.length, 0);
});

Deno.test("applyTagPlan ATP-4: a non-empty but fully non-actionable plan writes an empty preview WITHOUT connecting", async () => {
  // Every item has no keyword and no move -> zero actionable groups. The
  // fast path must skip connect/logout, not just for a literally empty plan.
  const fake = new ScriptedWriteClient({
    INBOX: [{ uid: 1, flags: new Set<string>() }],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  const plan: TagPlanItem[] = [
    { folder: "INBOX", uid: 1, keywords: [], financeMove: null },
    { folder: "Archive", uid: 2, keywords: [], financeMove: null },
  ];

  const result = await model.methods.applyTagPlan.execute(
    { ontologyModel: "ontology-test", _plan: plan, _client: factory },
    context,
  );

  assertEquals(result.dataHandles.length, 1);
  // No connection at all -- no open, no logout.
  assertEquals(fake.openedReadOnly.length, 0);
  assertEquals(fake.loggedOut, false);
  assertEquals(writes[0].spec, "tagPlanPreview");
  const data = writes[0].data as {
    keywordGroups: unknown[];
    moveGroups: unknown[];
    totals: Record<string, number>;
  };
  assertEquals(data.keywordGroups.length, 0);
  assertEquals(data.moveGroups.length, 0);
  assertEquals(data.totals.keywordGroupCount, 0);
  assertEquals(data.totals.moveGroupCount, 0);
});

Deno.test("applyTagPlan ATP-5: cross-chunk UIDVALIDITY divergence is flagged on the group, not silently overwritten", async () => {
  // A single (folder,keyword) group large enough to chunk across two fan-out
  // inspections; the mailbox reports a DIFFERENT uidValidity on the second
  // chunk. dryRun so the per-chunk mutate drift guard is not engaged -- this
  // is purely about faithful REPORTING of a mid-group renumbering.
  const n = MAX_UIDS + 5;
  const store: Record<string, { uid: number; flags: Set<string> }[]> = {
    INBOX: Array.from({ length: n }, (_, i) => ({
      uid: i + 1,
      flags: new Set<string>(),
    })),
  };
  const fake = new ScriptedWriteClient(store, 555, {
    uidValiditySequence: [555, 777], // chunk 1 -> 555, chunk 2 -> 777
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  const plan: TagPlanItem[] = Array.from({ length: n }, (_, i) => ({
    folder: "INBOX",
    uid: i + 1,
    keywords: ["cat/finance"],
    financeMove: null,
  }));

  await model.methods.applyTagPlan.execute(
    { ontologyModel: "ontology-test", _plan: plan, _client: factory },
    context,
  );

  assertEquals(writes[0].spec, "tagPlanPreview");
  const data = writes[0].data as {
    keywordGroups: Array<
      { uidValidity: number | null; uidValidityDiverged: boolean }
    >;
  };
  assertEquals(data.keywordGroups.length, 1);
  // First-seen value is kept as canonical; divergence is surfaced, not masked.
  assertEquals(data.keywordGroups[0].uidValidity, 555);
  assertEquals(data.keywordGroups[0].uidValidityDiverged, true);
});

// ---------------------------------------------------------------------------
// createFolder -- mailbox-level gated write (imap-create-folder work item).
// Every test injects a dedicated folder-only fixture (never a live
// mailbox); fixtures are depersonalized (synthetic "Lists/Example"-style
// paths, never real mailbox content).
// ---------------------------------------------------------------------------

/**
 * A scripted client backing createFolder tests. Tracks the live folder set
 * (mutated by a successful create, mirroring a real server), the hierarchy
 * delimiter LIST reports, and every mailboxCreate call. createFolder is
 * mailbox-level: it never reaches mailboxOpen/fetch/getMailboxLock/
 * messageFlagsAdd/messageFlagsRemove/messageMove, so every one of those
 * members throws if a regression ever routes through them.
 */
class ScriptedFolderClient implements ImapClientLike {
  mailboxCreateCalls: string[] = [];
  listCalls = 0;
  loggedOut = false;

  constructor(
    readonly folders: Set<string>,
    private readonly delimiter: string | false = "/",
    private readonly opts: {
      /**
       * Paths whose mailboxCreate call THROWS an ALREADYEXISTS-coded error
       * instead of imapflow's normal non-throwing `created:false` path --
       * exercises {@link isAlreadyExistsError}'s defense-in-depth for a
       * client that does not normalize it.
       */
      throwAlreadyExistsFor?: Set<string>;
      /** Paths whose mailboxCreate call throws a genuine (non-ALREADYEXISTS) error. */
      throwOtherFor?: Set<string>;
      /** Paths that report created:true but never actually appear in a later LIST (models a discrepancy). */
      silentlyFailToCreate?: Set<string>;
      /**
       * When set, the Nth (1-based) list() call throws -- models the
       * Phase-2 re-verification LIST failing AFTER folders were created
       * live (CF-1). E.g. 2 = first LIST (pre-check) succeeds, second LIST
       * (re-verify) throws.
       */
      throwOnListCall?: number;
      /**
       * When set, models a non-empty personal namespace prefix (e.g.
       * "INBOX."): both list() and mailboxCreate() internally normalize a
       * caller path by prepending this prefix (imapflow's normalizePath
       * behavior), so the server-canonical path differs from the raw
       * request (CF-2). The internal `folders` set stores canonical paths.
       */
      namespacePrefix?: string;
    } = {},
  ) {}

  /** Mirror imapflow normalizePath: prepend the namespace prefix if any. */
  private canon(path: string): string {
    const prefix = this.opts.namespacePrefix;
    if (!prefix) return path;
    if (path.toUpperCase() === "INBOX") return "INBOX";
    return path.startsWith(prefix) ? path : prefix + path;
  }

  connect(): Promise<void> {
    return Promise.resolve();
  }
  list(): Promise<ListEntry[]> {
    this.listCalls++;
    if (this.opts.throwOnListCall === this.listCalls) {
      return Promise.reject(
        new Error(`synthetic LIST failure on call ${this.listCalls}`),
      );
    }
    return Promise.resolve(
      [...this.folders].map((path) => ({
        path,
        name: path,
        delimiter: this.delimiter,
        flags: [] as string[],
        subscribed: true,
      })),
    );
  }
  status(): Promise<MailboxStatus> {
    throw new Error(
      "ScriptedFolderClient (folder fixture) has no STATUS support",
    );
  }
  mailboxOpen(): Promise<MailboxOpenResult> {
    throw new Error(
      "ScriptedFolderClient (folder fixture) never opens a mailbox",
    );
  }
  fetch(): AsyncIterable<FetchMessage> {
    throw new Error("ScriptedFolderClient (folder fixture) never fetches");
  }
  mailboxClose(): Promise<void> {
    throw new Error(
      "ScriptedFolderClient (folder fixture) never closes a mailbox",
    );
  }
  getMailboxLock(): Promise<MailboxLock> {
    throw new Error(
      "ScriptedFolderClient (folder fixture) never locks a mailbox",
    );
  }
  logout(): Promise<void> {
    this.loggedOut = true;
    return Promise.resolve();
  }
  messageFlagsAdd(): Promise<unknown> {
    throw new Error(
      "ScriptedFolderClient (folder fixture) has no message-write support",
    );
  }
  messageFlagsRemove(): Promise<unknown> {
    throw new Error(
      "ScriptedFolderClient (folder fixture) has no message-write support",
    );
  }
  messageMove(): Promise<unknown> {
    throw new Error(
      "ScriptedFolderClient (folder fixture) has no message-write support",
    );
  }
  mailboxCreate(path: string): Promise<{ path: string; created: boolean }> {
    // Record the RAW path createFolder called with (what the method sends).
    this.mailboxCreateCalls.push(path);
    // The fixture matches option Sets against the raw caller path, but the
    // server-canonical path (what list()/mailboxCreate return and store) is
    // namespace-normalized -- the CF-2 distinction under test.
    const canonical = this.canon(path);
    if (this.opts.throwOtherFor?.has(path)) {
      return Promise.reject(
        new Error(`synthetic create failure for ${path}`),
      );
    }
    if (this.opts.throwAlreadyExistsFor?.has(path)) {
      // ALREADYEXISTS means the server considers the mailbox present
      // (a race with another session) -- reflect that in the fixture's own
      // folder set so a post-creation re-LIST sees it, same as a real
      // server would.
      this.folders.add(canonical);
      const err = new Error(`Mailbox already exists: ${path}`) as Error & {
        serverResponseCode?: string;
      };
      err.serverResponseCode = "ALREADYEXISTS";
      return Promise.reject(err);
    }
    if (this.folders.has(canonical)) {
      return Promise.resolve({ path: canonical, created: false });
    }
    if (!this.opts.silentlyFailToCreate?.has(path)) {
      this.folders.add(canonical);
    }
    return Promise.resolve({ path: canonical, created: true });
  }
}

Deno.test("validateFolderPath rejects empty/whitespace-only paths and control characters", () => {
  assertThrows(() => validateFolderPath(""), Error, "empty");
  assertThrows(() => validateFolderPath("   "), Error, "empty");
  assertThrows(
    () => validateFolderPath("Lists/Exa\x01mple"),
    Error,
    "control character",
  );
  assertThrows(
    () => validateFolderPath("Lists\x7fExample"),
    Error,
    "control character",
  );
});

Deno.test("validateFolderPath rejects leading/trailing whitespace (CF-6: distinct non-idempotent path)", () => {
  // " INBOX" and "INBOX" are DISTINCT mailbox paths on the wire; silently
  // trimming could create the wrong mailbox, so reject rather than trim.
  assertThrows(() => validateFolderPath(" INBOX"), Error, "whitespace");
  assertThrows(() => validateFolderPath("INBOX "), Error, "whitespace");
  assertThrows(
    () => validateFolderPath("Lists/Example\t"),
    Error,
    "whitespace",
  );
});

Deno.test("validateFolderPath accepts ordinary mailbox paths (interior spaces, delimiters, punctuation)", () => {
  validateFolderPath("INBOX");
  validateFolderPath("Lists/Example");
  validateFolderPath("Notifications.Jira");
  validateFolderPath("My Folder"); // interior space is fine
});

Deno.test("isAlreadyExistsError recognizes serverResponseCode and message forms, and nothing else", () => {
  const coded = new Error("create failed") as Error & {
    serverResponseCode?: string;
  };
  coded.serverResponseCode = "ALREADYEXISTS";
  assertEquals(isAlreadyExistsError(coded), true);
  assertEquals(
    isAlreadyExistsError(new Error("NO [ALREADYEXISTS] Mailbox exists")),
    true,
  );
  assertEquals(isAlreadyExistsError(new Error("permission denied")), false);
  assertEquals(isAlreadyExistsError("not an Error"), false);
});

Deno.test("createFolder rejects an empty/control-char path before any connection, with zero mutation", async () => {
  const fake = new ScriptedFolderClient(new Set(["INBOX"]));
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  await assertRejects(
    () =>
      model.methods.createFolder.execute(
        { folders: ["Lists/Example", ""], dryRun: true, _client: factory },
        context,
      ),
    Error,
    "empty",
  );
  assertEquals(fake.listCalls, 0);
  assertEquals(fake.mailboxCreateCalls.length, 0);
  assertEquals(writes.length, 0);

  await assertRejects(
    () =>
      model.methods.createFolder.execute(
        {
          folders: ["Lists/Exa\x01mple"],
          dryRun: false,
          _client: factory,
        },
        context,
      ),
    Error,
    "control character",
  );
  assertEquals(fake.listCalls, 0);
  assertEquals(fake.mailboxCreateCalls.length, 0);
  assertEquals(writes.length, 0);
});

Deno.test("createFolder dryRun=true (default) performs ZERO mutation and the preview accurately marks exists vs would-create", async () => {
  const fake = new ScriptedFolderClient(
    new Set(["INBOX", "Lists/Example"]),
    ".",
  );
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  const result = await model.methods.createFolder.execute(
    {
      folders: ["INBOX", "Lists/Example", "Notifications/Jira"],
      _client: factory, // dryRun omitted -- default must be true
    },
    context,
  );

  assertEquals(fake.mailboxCreateCalls.length, 0);
  assertEquals(writes.length, 1);
  assertEquals(writes[0].spec, "createFolderPreview");
  const data = writes[0].data as {
    dryRun: boolean;
    delimiter: string | null;
    requestedCount: number;
    existingCount: number;
    wouldCreateCount: number;
    items: Array<
      { folder: string; existsAlready: boolean; wouldCreate: boolean }
    >;
  };
  assertEquals(data.dryRun, true);
  // The server's LIVE delimiter is echoed, never a hardcoded "/".
  assertEquals(data.delimiter, ".");
  assertEquals(data.requestedCount, 3);
  assertEquals(data.existingCount, 2);
  assertEquals(data.wouldCreateCount, 1);
  const byFolder = new Map(data.items.map((i) => [i.folder, i]));
  assertEquals(byFolder.get("INBOX"), {
    folder: "INBOX",
    existsAlready: true,
    wouldCreate: false,
  });
  assertEquals(byFolder.get("Lists/Example"), {
    folder: "Lists/Example",
    existsAlready: true,
    wouldCreate: false,
  });
  assertEquals(byFolder.get("Notifications/Jira"), {
    folder: "Notifications/Jira",
    existsAlready: false,
    wouldCreate: true,
  });
  assertEquals(result.dataHandles.length, 1);
});

Deno.test("createFolder dryRun=false creates an absent folder (mutate path calls mailboxCreate)", async () => {
  const fake = new ScriptedFolderClient(new Set(["INBOX"]));
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  await model.methods.createFolder.execute(
    { folders: ["Lists/Example"], dryRun: false, _client: factory },
    context,
  );

  assertEquals(fake.mailboxCreateCalls, ["Lists/Example"]);
  assertEquals(writes.length, 1);
  assertEquals(writes[0].spec, "createFolderResult");
  const data = writes[0].data as {
    dryRun: boolean;
    createdCount: number;
    alreadyExistedCount: number;
    items: Array<{
      folder: string;
      canonicalPath: string;
      existedBefore: boolean;
      created: boolean;
      alreadyExisted: boolean;
      verifiedExists: boolean;
    }>;
    discrepancies: unknown[];
  };
  assertEquals(data.dryRun, false);
  assertEquals(data.createdCount, 1);
  assertEquals(data.alreadyExistedCount, 0);
  assertEquals(data.items, [
    {
      folder: "Lists/Example",
      canonicalPath: "Lists/Example",
      existedBefore: false,
      created: true,
      alreadyExisted: false,
      verifiedExists: true,
    },
  ]);
  assertEquals(data.discrepancies, []);
  assertEquals(fake.folders.has("Lists/Example"), true);
});

Deno.test("createFolder is idempotent: a folder already present is skipped with NO mailboxCreate call", async () => {
  const fake = new ScriptedFolderClient(new Set(["INBOX", "Lists/Example"]));
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  await model.methods.createFolder.execute(
    { folders: ["Lists/Example"], dryRun: false, _client: factory },
    context,
  );

  // No create call at all -- not even an idempotent one.
  assertEquals(fake.mailboxCreateCalls.length, 0);
  const data = writes[0].data as {
    createdCount: number;
    alreadyExistedCount: number;
    items: Array<{
      folder: string;
      canonicalPath: string;
      existedBefore: boolean;
      created: boolean;
      alreadyExisted: boolean;
      verifiedExists: boolean;
    }>;
  };
  assertEquals(data.createdCount, 0);
  assertEquals(data.alreadyExistedCount, 1);
  assertEquals(data.items, [
    {
      folder: "Lists/Example",
      canonicalPath: "Lists/Example",
      existedBefore: true,
      created: false,
      alreadyExisted: true,
      verifiedExists: true,
    },
  ]);
});

Deno.test("createFolder treats a server ALREADYEXISTS response as SUCCESS, not an error", async () => {
  // The existence pre-check (Phase 1 LIST) reports the folder absent -- a
  // race with another session -- so createFolder still calls mailboxCreate;
  // the fake throws an ALREADYEXISTS-coded error from THAT call.
  const fake = new ScriptedFolderClient(
    new Set(["INBOX"]),
    "/",
    { throwAlreadyExistsFor: new Set(["Lists/Example"]) },
  );
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  await model.methods.createFolder.execute(
    { folders: ["Lists/Example"], dryRun: false, _client: factory },
    context,
  );

  assertEquals(fake.mailboxCreateCalls, ["Lists/Example"]);
  const data = writes[0].data as {
    createdCount: number;
    alreadyExistedCount: number;
    discrepancies: unknown[];
    error: string | undefined;
  };
  assertEquals(data.error, undefined);
  assertEquals(data.createdCount, 0);
  assertEquals(data.alreadyExistedCount, 1);
  // The thrown ALREADYEXISTS was swallowed as success (isAlreadyExistsError),
  // never surfaced as data.error, and the Phase-2 re-LIST confirms the
  // folder is genuinely present (no discrepancy).
  assertEquals(data.discrepancies, []);
});

Deno.test("createFolder fans out over multiple folders in ONE call", async () => {
  const fake = new ScriptedFolderClient(new Set(["INBOX"]));
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  await model.methods.createFolder.execute(
    {
      folders: ["Lists/Example", "Notifications/Jira", "Finance"],
      dryRun: false,
      _client: factory,
    },
    context,
  );

  // All three absent folders created by ONE method call (3 mailboxCreate
  // calls total -- IMAP CREATE has no multi-path verb -- but exactly ONE
  // createFolder execution, never N separate calls into this method).
  assertEquals(
    fake.mailboxCreateCalls.sort(),
    ["Finance", "Lists/Example", "Notifications/Jira"],
  );
  assertEquals(writes.length, 1);
  const data = writes[0].data as { createdCount: number; items: unknown[] };
  assertEquals(data.createdCount, 3);
  assertEquals(data.items.length, 3);
});

Deno.test("createFolder de-duplicates requested folders before processing", async () => {
  const fake = new ScriptedFolderClient(new Set(["INBOX"]));
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  await model.methods.createFolder.execute(
    {
      folders: ["Lists/Example", "Lists/Example"],
      dryRun: false,
      _client: factory,
    },
    context,
  );

  assertEquals(fake.mailboxCreateCalls, ["Lists/Example"]);
  const data = writes[0].data as { requestedCount: number; items: unknown[] };
  assertEquals(data.requestedCount, 1);
  assertEquals(data.items.length, 1);
});

Deno.test("createFolder mid-batch failure (non-ALREADYEXISTS) persists evidence for folders already processed before surfacing the error", async () => {
  const fake = new ScriptedFolderClient(
    new Set(["INBOX", "Lists/Example"]),
    "/",
    { throwOtherFor: new Set(["Quiet"]) },
  );
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  await assertRejects(
    () =>
      model.methods.createFolder.execute(
        {
          // "Lists/Example" (already exists, no create call) is processed
          // first; "Finance" is created successfully; "Quiet" then throws.
          folders: ["Lists/Example", "Finance", "Quiet"],
          dryRun: false,
          _client: factory,
        },
        context,
      ),
    Error,
    "synthetic create failure for Quiet",
  );

  // The audit is never left empty on throw: partial evidence for the
  // folders already processed (the pre-existing skip + the successful
  // create) was persisted BEFORE the exception propagated.
  assertEquals(writes.length, 1);
  assertEquals(writes[0].spec, "createFolderResult");
  const data = writes[0].data as {
    error: string;
    items: Array<{ folder: string }>;
  };
  assertEquals(data.error.includes("synthetic create failure for Quiet"), true);
  const processedFolders = data.items.map((i) => i.folder).sort();
  assertEquals(processedFolders, ["Finance", "Lists/Example"]);
  // "Quiet" itself never made it into an items row -- it threw before one
  // could be recorded for it, which is exactly why the partial evidence
  // (not a silently-lost exception) is the fail-closed behavior under test.
  assertEquals(fake.mailboxCreateCalls, ["Finance", "Quiet"]);
});

Deno.test("createFolder discrepancies[]: a folder that reports created but is still absent on re-LIST is flagged, not silently trusted", async () => {
  const fake = new ScriptedFolderClient(
    new Set(["INBOX"]),
    "/",
    { silentlyFailToCreate: new Set(["Lists/Example"]) },
  );
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  await model.methods.createFolder.execute(
    { folders: ["Lists/Example"], dryRun: false, _client: factory },
    context,
  );

  const data = writes[0].data as {
    createdCount: number;
    discrepancies: Array<{ folder: string; reason: string }>;
    items: Array<{ folder: string; verifiedExists: boolean }>;
  };
  assertEquals(data.items[0].verifiedExists, false);
  assertEquals(data.discrepancies, [
    {
      folder: "Lists/Example",
      reason: "requested but still absent after create",
    },
  ]);
  // CF-5: a claimed-but-unverified create does NOT inflate createdCount; it
  // lives in discrepancies[] instead.
  assertEquals(data.createdCount, 0);
});

Deno.test("createFolder CF-1: a Phase-2 re-LIST failure AFTER a live create still persists createFolderResult evidence (created folder + error) before propagating", async () => {
  // throwOnListCall: 2 -- the first LIST (Phase-1 pre-check) succeeds, the
  // folder is created live, then the second LIST (Phase-2 re-verify) throws.
  // Without the CF-1 fix the whole call would throw with ZERO
  // createFolderResult written, losing the record of a real mutation.
  const fake = new ScriptedFolderClient(
    new Set(["INBOX"]),
    "/",
    { throwOnListCall: 2 },
  );
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  await assertRejects(
    () =>
      model.methods.createFolder.execute(
        { folders: ["Lists/Example"], dryRun: false, _client: factory },
        context,
      ),
    Error,
    "synthetic LIST failure on call 2",
  );

  // The create actually ran (before the Phase-2 LIST threw)...
  assertEquals(fake.mailboxCreateCalls, ["Lists/Example"]);
  // ...and the audit is NOT empty: a createFolderResult with the created
  // folder plus the error was persisted BEFORE the exception propagated.
  assertEquals(writes.length, 1);
  assertEquals(writes[0].spec, "createFolderResult");
  const data = writes[0].data as {
    error: string;
    items: Array<{ folder: string; created: boolean }>;
    discrepancies: unknown[];
  };
  assertEquals(data.error.includes("synthetic LIST failure on call 2"), true);
  assertEquals(data.items.length, 1);
  assertEquals(data.items[0].folder, "Lists/Example");
  assertEquals(data.items[0].created, true);
  // Phase-2 never completed, so no discrepancy was computed.
  assertEquals(data.discrepancies, []);
});

Deno.test("createFolder CF-2: a successful create under a non-empty namespace prefix is NOT a false discrepancy; items carry the canonical (prefixed) path", async () => {
  // Models imapflow normalizePath: both list() and mailboxCreate() return
  // the namespace-prefixed canonical path, while the caller passes
  // un-prefixed paths. Before the CF-2 fix (comparing the raw request
  // against the re-LIST) this produced a false discrepancy and a wrong
  // canonical path; after the fix the canonical path (resp.path) is used.
  const fake = new ScriptedFolderClient(
    new Set(["INBOX"]),
    ".",
    { namespacePrefix: "INBOX." },
  );
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  await model.methods.createFolder.execute(
    { folders: ["Lists", "Finance"], dryRun: false, _client: factory },
    context,
  );

  assertEquals(writes.length, 1);
  assertEquals(writes[0].spec, "createFolderResult");
  const data = writes[0].data as {
    createdCount: number;
    discrepancies: Array<{ folder: string; reason: string }>;
    items: Array<
      { folder: string; canonicalPath: string; created: boolean }
    >;
  };
  // No false discrepancy despite raw != canonical.
  assertEquals(data.discrepancies, []);
  assertEquals(data.createdCount, 2);
  const byFolder = new Map(data.items.map((i) => [i.folder, i]));
  // Each item records the server-canonical (prefixed) path actually created.
  assertEquals(byFolder.get("Lists")?.canonicalPath, "INBOX.Lists");
  assertEquals(byFolder.get("Finance")?.canonicalPath, "INBOX.Finance");
  assertEquals(byFolder.get("Lists")?.created, true);
  // The prefixed folders are genuinely present on the (fixture) server.
  assertEquals(fake.folders.has("INBOX.Lists"), true);
  assertEquals(fake.folders.has("INBOX.Finance"), true);
});

Deno.test("createFolder CF-3: an over-cap folder set is rejected with a batching hint before any connection", async () => {
  const fake = new ScriptedFolderClient(new Set(["INBOX"]));
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();

  const tooMany = Array.from(
    { length: MAX_FOLDERS + 1 },
    (_, i) => `Lists/Example-${i}`,
  );

  await assertRejects(
    () =>
      model.methods.createFolder.execute(
        { folders: tooMany, dryRun: false, _client: factory },
        context,
      ),
    Error,
    "the cap",
  );
  // Rejected before connecting: no LIST, no create, no evidence written.
  assertEquals(fake.listCalls, 0);
  assertEquals(fake.mailboxCreateCalls.length, 0);
  assertEquals(writes.length, 0);

  // Exactly MAX_FOLDERS is allowed through.
  const exactlyMax = Array.from(
    { length: MAX_FOLDERS },
    (_, i) => `Lists/Example-${i}`,
  );
  await model.methods.createFolder.execute(
    { folders: exactlyMax, dryRun: true, _client: factory },
    context,
  );
  assertEquals(writes.length, 1);
  assertEquals(writes[0].spec, "createFolderPreview");
});

// ---------------------------------------------------------------------------
// fetchMessage -- full-body read path (EXAMINE; postal-mime decode).
//
// ONE folder per call (an IMAP UID is unique only within one folder). Uses a
// pre-fetch size gate: FETCH 1 is {uid,size} (no source); FETCH 2 pulls source
// ONLY for under-cap UIDs. Decode-correctness tests feed SYNTHETIC RFC822
// source strings through the REAL defaultParser (postal-mime), per the SB-9
// lesson -- no parallel reimplementation. The `_parse` seam is reserved for
// edge cases awkward to express as real MIME (e.g. a decoder that throws).
// Every fixture is depersonalized (RFC 2606 reserved domains, synthetic
// bodies, numeric UIDs).
// ---------------------------------------------------------------------------

/** One synthetic message a {@link ScriptedFetchClient} can serve. */
interface FetchFixtureMessage {
  uid: number;
  flags?: Set<string> | string[];
  /** The server's RFC822.SIZE (undefined models a server that reports none). */
  size?: number;
  envelope?: FetchMessage["envelope"];
  headers?: string;
  source?: string | Uint8Array;
}

/**
 * A scripted read-only client for fetchMessage. It is QUERY-AWARE, faithfully
 * modelling the two-fetch size gate: a `source` fetch yields ONLY {uid,source}
 * (so a withheld over-cap UID is provably never pulled), while a non-source
 * fetch yields {uid,size,envelope,flags,headers} (NO source). Records every
 * mailboxOpen (to assert EXAMINE-only), every fetch (to assert the two fan-out
 * calls and their ranges), and THROWS from getMailboxLock -- the read-write
 * seam must never be reached by a structurally read-only method.
 */
class ScriptedFetchClient implements ImapClientLike {
  openedReadOnly: boolean[] = [];
  closedCount = 0;
  loggedOut = false;
  lockCalls = 0;
  fetchCalls: Array<{ range: string; query: Record<string, unknown> }> = [];
  private openFolder = "";

  constructor(
    private readonly byFolder: Record<string, FetchFixtureMessage[]>,
    // `null` models a server that reports NO UIDVALIDITY (distinct from the
    // 777 default; a plain `undefined` would re-trigger the default param).
    private readonly uidValidity: number | null = 777,
    private readonly opts: {
      throwOnFetch?: boolean;
      // When true, the HEADER (non-source) fetch also yields one message with
      // uid undefined -- models a server returning a null UID (FM-5).
      emitNullUid?: boolean;
    } = {},
  ) {}

  connect(): Promise<void> {
    return Promise.resolve();
  }
  list(): Promise<ListEntry[]> {
    return Promise.resolve([]);
  }
  status(_path: string, _query: StatusQuery): Promise<MailboxStatus> {
    return Promise.resolve({});
  }
  mailboxOpen(
    path: string,
    opts: { readOnly: boolean },
  ): Promise<MailboxOpenResult> {
    this.openFolder = path;
    this.openedReadOnly.push(opts.readOnly);
    return Promise.resolve({
      exists: (this.byFolder[path] ?? []).length,
      uidValidity: this.uidValidity === null ? undefined : this.uidValidity,
    });
  }
  async *fetch(
    range: string,
    query: FetchQuery,
  ): AsyncIterable<FetchMessage> {
    this.fetchCalls.push({
      range,
      query: query as unknown as Record<string, unknown>,
    });
    if (this.opts.throwOnFetch) {
      throw new Error("synthetic fetch failure");
    }
    const wantSource = query.source === true;
    const requested = new Set(range.split(",").map((s) => Number(s)));
    for (const m of this.byFolder[this.openFolder] ?? []) {
      if (!requested.has(m.uid)) continue;
      if (wantSource) {
        // Source fetch: ONLY uid + source (never the header fields).
        yield await Promise.resolve({ uid: m.uid, source: m.source });
      } else {
        // Header/size fetch: everything EXCEPT source.
        yield await Promise.resolve({
          uid: m.uid,
          flags: m.flags,
          size: m.size,
          envelope: m.envelope,
          headers: m.headers,
        });
      }
    }
    if (!wantSource && this.opts.emitNullUid) {
      yield await Promise.resolve({ uid: undefined, size: 10 });
    }
  }
  mailboxClose(): Promise<void> {
    this.closedCount++;
    return Promise.resolve();
  }
  getMailboxLock(): Promise<MailboxLock> {
    this.lockCalls++;
    throw new Error(
      "fetchMessage must never open read-write (EXAMINE only)",
    );
  }
  logout(): Promise<void> {
    this.loggedOut = true;
    return Promise.resolve();
  }
  messageFlagsAdd(): Promise<unknown> {
    throw new Error("fetchMessage fixture has no write support");
  }
  messageFlagsRemove(): Promise<unknown> {
    throw new Error("fetchMessage fixture has no write support");
  }
  messageMove(): Promise<unknown> {
    throw new Error("fetchMessage fixture has no write support");
  }
  mailboxCreate(): Promise<{ path: string; created: boolean }> {
    throw new Error("fetchMessage fixture has no write support");
  }
}

/** Index of the source (second) fetch in a healthy two-fetch run. */
function sourceFetchCall(
  fake: ScriptedFetchClient,
): { range: string; query: Record<string, unknown> } | undefined {
  return fake.fetchCalls.find((c) => c.query.source === true);
}

/** A single-part text/plain message with two clean (whitespace-bounded) URLs. */
const PLAIN_SRC = [
  "From: Alice Example <alice@example.com>",
  "To: user@example.net",
  "Subject: Plain hello",
  "Message-ID: <plain-1@example.com>",
  "Content-Type: text/plain; charset=utf-8",
  "",
  "Hello plain body. Links: http://example.com/a and https://example.net/b end.",
  "",
].join("\r\n");

/** A multipart/alternative message: a text/plain and a text/html part. */
const ALT_SRC = [
  "From: Bob <bob@example.org>",
  "To: user@example.net",
  "Subject: Alt message",
  "Message-ID: <alt-1@example.org>",
  'Content-Type: multipart/alternative; boundary="BOUNDARY"',
  "",
  "--BOUNDARY",
  "Content-Type: text/plain; charset=utf-8",
  "",
  "Text part visit http://example.com/text",
  "--BOUNDARY",
  "Content-Type: text/html; charset=utf-8",
  "",
  '<p>Html part <a href="https://example.com/html">link</a> and ' +
  "http://example.com/text</p>",
  "--BOUNDARY--",
  "",
].join("\r\n");

/** A multipart/mixed message with one text part and one small attachment. */
const ATTACH_SRC = [
  "From: Carol <carol@example.com>",
  "To: user@example.net",
  "Subject: With attachment",
  "Message-ID: <attach-1@example.com>",
  'Content-Type: multipart/mixed; boundary="MIX"',
  "",
  "--MIX",
  "Content-Type: text/plain; charset=utf-8",
  "",
  "Body with attachment.",
  "--MIX",
  'Content-Type: text/plain; name="note.txt"',
  'Content-Disposition: attachment; filename="note.txt"',
  "Content-Transfer-Encoding: base64",
  "",
  // base64 of "hello attachment" (16 bytes)
  "aGVsbG8gYXR0YWNobWVudA==",
  "--MIX--",
  "",
].join("\r\n");

Deno.test("extractLinks dedupes http/https URLs across text and html, first-seen order", () => {
  const text = "see http://example.com/text and http://example.com/text again";
  const html =
    '<a href="https://example.com/html">x</a> http://example.com/text';
  assertEquals(extractLinks(text, html), [
    "http://example.com/text",
    "https://example.com/html",
  ]);
  // Null/undefined inputs are tolerated (no body of that kind).
  assertEquals(extractLinks(null, "visit https://example.org/z"), [
    "https://example.org/z",
  ]);
  assertEquals(extractLinks(null, null), []);
});

Deno.test("sourceByteLength counts UTF-8 bytes for strings and byteLength for bytes", () => {
  assertEquals(sourceByteLength("abc"), 3);
  // A 2-byte UTF-8 code point ("e" with acute accent) counts as 2 bytes.
  assertEquals(sourceByteLength("é"), 2);
  assertEquals(sourceByteLength(new Uint8Array([1, 2, 3, 4])), 4);
});

Deno.test("truncateUtf8ToBytes cuts on byte boundaries without splitting a code point", () => {
  // Pure ASCII: cut is exact.
  assertEquals(truncateUtf8ToBytes("abcdef", 3), "abc");
  // Under the cap: returned unchanged.
  assertEquals(truncateUtf8ToBytes("abc", 10), "abc");
  // Each "é" is 2 UTF-8 bytes. A cap of 3 bytes must NOT split the 2nd one:
  // it keeps one full "é" (2 bytes) and drops the partial second, never
  // emitting a U+FFFD replacement char (a UTF-16 .slice(0,3) would keep 3
  // CHARACTERS = 6 bytes, the bug this guards against).
  const multi = "ééé";
  const out = truncateUtf8ToBytes(multi, 3);
  assertEquals(out, "é");
  assertEquals(sourceByteLength(out) <= 3, true);
  assertEquals(out.includes("�"), false);
});

Deno.test("checkFetchUidCap rejects over MAX_FETCH_UIDS with a batching hint", () => {
  const over = Array.from({ length: MAX_FETCH_UIDS + 1 }, (_, i) => i + 1);
  assertThrows(() => checkFetchUidCap(over), Error, "cap is 25");
  // Exactly the cap is allowed.
  const exact = Array.from({ length: MAX_FETCH_UIDS }, (_, i) => i + 1);
  checkFetchUidCap(exact);
});

Deno.test("defaultParser decodes a single-part text/plain message (real postal-mime)", async () => {
  const parsed = await defaultParser(PLAIN_SRC);
  assertEquals(
    parsed.text,
    "Hello plain body. Links: http://example.com/a " +
      "and https://example.net/b end.\n",
  );
  assertEquals(parsed.html, null);
  assertEquals(parsed.attachments, []);
});

Deno.test("buildMessageBody withholds an over-cap body (source undefined, server size over cap)", async () => {
  const msg: FetchMessage = {
    uid: 55,
    flags: new Set(["\\Seen"]),
    size: MAX_BODY_BYTES + 10,
    envelope: { subject: "Oversized" },
  };
  // source undefined == withheld; serverSize over the cap.
  const rec = await buildMessageBody(
    msg,
    "INBOX",
    undefined,
    MAX_BODY_BYTES + 10,
    defaultParser,
  );
  assertEquals(rec.uid, 55);
  assertEquals(rec.subject, "Oversized");
  assertEquals(rec.text, null);
  assertEquals(rec.html, null);
  assertEquals(rec.attachments, []);
  assertEquals(rec.links, []);
  assertEquals(rec.truncated, true);
  assertEquals(rec.sourceBytes, MAX_BODY_BYTES + 10);
  assertEquals(rec.error, null);
});

Deno.test("fetchMessage decodes a single-part text/plain body and extracts links", async () => {
  const fake = new ScriptedFetchClient({
    INBOX: [{
      uid: 101,
      flags: new Set(["\\Seen"]),
      size: sourceByteLength(PLAIN_SRC),
      envelope: {
        from: [{ name: "Alice Example", address: "alice@example.com" }],
        subject: "Plain hello",
        messageId: "<plain-1@example.com>",
      },
      source: PLAIN_SRC,
    }],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();
  const result = await model.methods.fetchMessage.execute(
    { folder: "INBOX", uids: [101], _client: factory },
    context,
  );

  assertEquals(result.dataHandles.length, 1);
  assertEquals(writes.length, 1);
  assertEquals(writes[0].spec, "messageBody");
  assertEquals(writes[0].name, "message:INBOX:101");
  const d = writes[0].data as Record<string, unknown>;
  assertEquals(d.uid, 101);
  assertEquals(d.folder, "INBOX");
  assertEquals(d.subject, "Plain hello");
  assertEquals(
    d.text,
    "Hello plain body. Links: http://example.com/a and " +
      "https://example.net/b end.\n",
  );
  assertEquals(d.html, null);
  assertEquals(d.attachments, []);
  assertEquals(d.links, [
    "http://example.com/a",
    "https://example.net/b",
  ]);
  assertEquals(d.truncated, false);
  assertEquals(d.sourceBytes, sourceByteLength(PLAIN_SRC));
  assertEquals(d.error, null);
  assertEquals(typeof d.retrievedAt, "string");
});

Deno.test("fetchMessage decodes multipart/alternative text+html and dedupes links across both", async () => {
  const fake = new ScriptedFetchClient({
    INBOX: [{
      uid: 202,
      size: sourceByteLength(ALT_SRC),
      source: ALT_SRC,
      envelope: { subject: "Alt" },
    }],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();
  await model.methods.fetchMessage.execute(
    { folder: "INBOX", uids: [202], _client: factory },
    context,
  );
  const d = writes[0].data as Record<string, unknown>;
  assertEquals(d.text, "Text part visit http://example.com/text\n");
  assertEquals(
    d.html,
    '<p>Html part <a href="https://example.com/html">link</a> and ' +
      "http://example.com/text</p>\n",
  );
  // http://example.com/text appears in BOTH parts but is recorded once;
  // the html-only https URL follows it in first-seen order.
  assertEquals(d.links, [
    "http://example.com/text",
    "https://example.com/html",
  ]);
  assertEquals(d.error, null);
});

Deno.test("fetchMessage records attachments as METADATA ONLY (no content leaks)", async () => {
  const fake = new ScriptedFetchClient({
    INBOX: [{
      uid: 303,
      size: sourceByteLength(ATTACH_SRC),
      source: ATTACH_SRC,
      envelope: { subject: "Attach" },
    }],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();
  await model.methods.fetchMessage.execute(
    { folder: "INBOX", uids: [303], _client: factory },
    context,
  );
  const d = writes[0].data as Record<string, unknown>;
  assertEquals(d.text, "Body with attachment.\n");
  assertEquals(d.html, null);
  const atts = d.attachments as Array<Record<string, unknown>>;
  assertEquals(atts.length, 1);
  assertEquals(atts[0].filename, "note.txt");
  assertEquals(atts[0].contentType, "text/plain");
  assertEquals(atts[0].size, 16);
  assertEquals(atts[0].contentId, null);
  // The decoded attachment CONTENT must never be carried into the record.
  assertEquals(Object.keys(atts[0]).includes("content"), false);
});

Deno.test("fetchMessage is EXAMINE-only (single folder): never opens read-write, always closes, never sets a lock", async () => {
  const fake = new ScriptedFetchClient({
    INBOX: [
      { uid: 101, size: sourceByteLength(PLAIN_SRC), source: PLAIN_SRC },
      { uid: 102, size: sourceByteLength(ALT_SRC), source: ALT_SRC },
    ],
  });
  const factory: ClientFactory = () => fake;
  const { context } = makeContext();
  await model.methods.fetchMessage.execute(
    { folder: "INBOX", uids: [101, 102], _client: factory },
    context,
  );
  // ONE folder == ONE open, read-only (EXAMINE).
  assertEquals(fake.openedReadOnly, [true]);
  // The read-write seam was NEVER reached.
  assertEquals(fake.lockCalls, 0);
  // The mailbox was closed once; the session logged out.
  assertEquals(fake.closedCount, 1);
  assertEquals(fake.loggedOut, true);
  // The size (first) fetch does NOT ask for source; the source (second) does.
  assertEquals(fake.fetchCalls[0].query.source, undefined);
  assertEquals(fake.fetchCalls[0].query.size, true);
  assertEquals(sourceFetchCall(fake)?.query.source, true);
});

Deno.test("fetchMessage uses exactly TWO fan-out fetches over a UID set (size then source), never per-UID", async () => {
  const fake = new ScriptedFetchClient({
    INBOX: [
      { uid: 101, size: sourceByteLength(PLAIN_SRC), source: PLAIN_SRC },
      { uid: 102, size: sourceByteLength(ALT_SRC), source: ALT_SRC },
      { uid: 103, size: sourceByteLength(ATTACH_SRC), source: ATTACH_SRC },
    ],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();
  const result = await model.methods.fetchMessage.execute(
    { folder: "INBOX", uids: [101, 102, 103], _client: factory },
    context,
  );
  assertEquals(result.dataHandles.length, 3);
  assertEquals(writes.length, 3);
  // Exactly two fetches total: ONE size fetch + ONE source fetch.
  assertEquals(fake.fetchCalls.length, 2);
  // Each carried the whole (under-cap) UID set on one command line.
  assertEquals(fake.fetchCalls[0].range, "101,102,103");
  assertEquals(sourceFetchCall(fake)?.range, "101,102,103");
});

Deno.test("fetchMessage de-duplicates the UID set before fetching", async () => {
  const fake = new ScriptedFetchClient({
    INBOX: [
      { uid: 101, size: sourceByteLength(PLAIN_SRC), source: PLAIN_SRC },
      { uid: 102, size: sourceByteLength(ALT_SRC), source: ALT_SRC },
    ],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();
  await model.methods.fetchMessage.execute(
    { folder: "INBOX", uids: [101, 101, 102, 102, 101], _client: factory },
    context,
  );
  // Each UID appears once in both fetch ranges; two records written.
  assertEquals(fake.fetchCalls[0].range, "101,102");
  assertEquals(sourceFetchCall(fake)?.range, "101,102");
  assertEquals(writes.length, 2);
});

Deno.test("fetchMessage refuses on a uidValidity mismatch (fail-closed), no records, mailbox closed", async () => {
  const fake = new ScriptedFetchClient(
    { INBOX: [{ uid: 101, size: 10, source: PLAIN_SRC }] },
    777,
  );
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();
  await assertRejects(
    () =>
      model.methods.fetchMessage.execute(
        { folder: "INBOX", uids: [101], uidValidity: 999, _client: factory },
        context,
      ),
    Error,
    "stale selection",
  );
  assertEquals(writes.length, 0);
  // Opened read-only, no fetch issued, still closed on the refusal path.
  assertEquals(fake.openedReadOnly, [true]);
  assertEquals(fake.fetchCalls.length, 0);
  assertEquals(fake.closedCount, 1);
  assertEquals(fake.lockCalls, 0);
});

Deno.test("fetchMessage fails closed when uidValidity is requested but unverifiable", async () => {
  const fake = new ScriptedFetchClient(
    { INBOX: [{ uid: 101, size: 10, source: PLAIN_SRC }] },
    null, // server reports no UIDVALIDITY
  );
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();
  await assertRejects(
    () =>
      model.methods.fetchMessage.execute(
        { folder: "INBOX", uids: [101], uidValidity: 777, _client: factory },
        context,
      ),
    Error,
    "did not report a live UIDVALIDITY",
  );
  assertEquals(writes.length, 0);
  assertEquals(fake.closedCount, 1);
});

Deno.test("fetchMessage rejects an over-cap UID set before connecting", async () => {
  const fake = new ScriptedFetchClient({ INBOX: [] });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();
  const tooMany = Array.from({ length: MAX_FETCH_UIDS + 1 }, (_, i) => i + 1);
  await assertRejects(
    () =>
      model.methods.fetchMessage.execute(
        { folder: "INBOX", uids: tooMany, _client: factory },
        context,
      ),
    Error,
    "cap is 25",
  );
  // Rejected before any network/open/fetch and before any evidence is written.
  assertEquals(fake.openedReadOnly.length, 0);
  assertEquals(fake.fetchCalls.length, 0);
  assertEquals(writes.length, 0);
});

Deno.test("fetchMessage withholds an over-cap body: null text/html, truncated, server size, and the source fetch did NOT pull it", async () => {
  const bigSize = MAX_BODY_BYTES + 500;
  const fake = new ScriptedFetchClient({
    INBOX: [
      // Over-cap by SERVER size; its `source` must never be read.
      { uid: 909, size: bigSize, source: "SHOULD-NEVER-BE-FETCHED" },
      // A normal under-cap neighbour, to prove the batch still proceeds.
      { uid: 101, size: sourceByteLength(PLAIN_SRC), source: PLAIN_SRC },
    ],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();
  await model.methods.fetchMessage.execute(
    { folder: "INBOX", uids: [909, 101], _client: factory },
    context,
  );
  // Both UIDs got records.
  assertEquals(writes.length, 2);
  const over = writes.find((w) => w.name === "message:INBOX:909")!
    .data as Record<string, unknown>;
  assertEquals(over.text, null);
  assertEquals(over.html, null);
  assertEquals(over.attachments, []);
  assertEquals(over.links, []);
  assertEquals(over.truncated, true);
  // sourceBytes == the SERVER size, since we never pulled the body.
  assertEquals(over.sourceBytes, bigSize);
  assertEquals(over.error, null);
  // PROOF we did not pull it: the source fetch range excludes 909.
  const srcRange = sourceFetchCall(fake)?.range ?? "";
  assertEquals(srcRange.split(",").includes("909"), false);
  assertEquals(srcRange, "101");
  // The under-cap neighbour decoded normally.
  const under = writes.find((w) => w.name === "message:INBOX:101")!
    .data as Record<string, unknown>;
  assertEquals(under.truncated, false);
  assertEquals(typeof under.text, "string");
});

Deno.test("fetchMessage byte-truncates a no-server-size body that exceeds the cap (real UTF-8, not UTF-16 chars)", async () => {
  // A multibyte body with NO server size -> included in the source fetch ->
  // its ACTUAL bytes exceed the cap -> byte-accurate truncation.
  const bodyChars = MAX_BODY_BYTES; // each "é" is 2 bytes -> ~2x the cap
  const body = "é".repeat(bodyChars);
  const bigSrc = [
    "From: Multi <multi@example.com>",
    "To: user@example.net",
    "Subject: Multibyte",
    "Content-Type: text/plain; charset=utf-8",
    "",
    body,
    "",
  ].join("\r\n");
  const fake = new ScriptedFetchClient({
    INBOX: [{ uid: 808, size: undefined, source: bigSrc }],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();
  await model.methods.fetchMessage.execute(
    { folder: "INBOX", uids: [808], _client: factory },
    context,
  );
  // No server size -> the UID WAS included in the source fetch.
  assertEquals(sourceFetchCall(fake)?.range, "808");
  const d = writes[0].data as Record<string, unknown>;
  assertEquals(d.truncated, true);
  // sourceBytes is the ACTUAL fetched length (over the cap).
  assertEquals(d.sourceBytes, sourceByteLength(bigSrc));
  assertEquals((d.sourceBytes as number) > MAX_BODY_BYTES, true);
  // The stored text is capped to AT MOST MAX_BODY_BYTES *bytes* (not chars),
  // cut on a code-point boundary (no replacement char).
  const text = d.text as string;
  assertEquals(sourceByteLength(text) <= MAX_BODY_BYTES, true);
  assertEquals(text.includes("�"), false);
});

Deno.test("fetchMessage isolates a per-message parse throw: that UID records an error, others still decode", async () => {
  // A decoder that throws for a poisoned source and defers to the real parser
  // otherwise -- the `_parse` seam used for an edge case not easily expressed
  // as real MIME (a decoder failure).
  const throwingParse: MimeParser = (source) => {
    const s = typeof source === "string"
      ? source
      : new TextDecoder().decode(source);
    if (s.includes("POISON")) {
      return Promise.reject(new Error("decode blew up: hostile MIME"));
    }
    return defaultParser(source);
  };
  const poison = [
    "From: Evil <evil@example.com>",
    "Subject: Poison",
    "Content-Type: text/plain; charset=utf-8",
    "",
    "POISON payload",
    "",
  ].join("\r\n");
  const fake = new ScriptedFetchClient({
    INBOX: [
      { uid: 401, size: sourceByteLength(poison), source: poison },
      { uid: 402, size: sourceByteLength(PLAIN_SRC), source: PLAIN_SRC },
    ],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();
  const result = await model.methods.fetchMessage.execute(
    {
      folder: "INBOX",
      uids: [401, 402],
      _client: factory,
      _parse: throwingParse,
    },
    context,
  );
  // The batch did NOT abort: both UIDs produced a record.
  assertEquals(result.dataHandles.length, 2);
  const bad = writes.find((w) => w.name === "message:INBOX:401")!
    .data as Record<string, unknown>;
  assertEquals(bad.error, "decode blew up: hostile MIME");
  assertEquals(bad.text, null);
  assertEquals(bad.html, null);
  assertEquals(bad.attachments, []);
  assertEquals(bad.links, []);
  // sourceBytes still recorded (we DID pull the under-cap source).
  assertEquals(bad.sourceBytes, sourceByteLength(poison));
  // The healthy neighbour decoded fully with no error.
  const good = writes.find((w) => w.name === "message:INBOX:402")!
    .data as Record<string, unknown>;
  assertEquals(good.error, null);
  assertEquals(typeof good.text, "string");
});

Deno.test("fetchMessage skips a message the server reports with a null UID (never names message:...:null)", async () => {
  const fake = new ScriptedFetchClient(
    {
      INBOX: [{
        uid: 101,
        size: sourceByteLength(PLAIN_SRC),
        source: PLAIN_SRC,
      }],
    },
    777,
    { emitNullUid: true },
  );
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();
  const result = await model.methods.fetchMessage.execute(
    { folder: "INBOX", uids: [101], _client: factory },
    context,
  );
  // Only the real UID was written; the null-UID message was skipped.
  assertEquals(result.dataHandles.length, 1);
  assertEquals(writes.length, 1);
  assertEquals(writes[0].name, "message:INBOX:101");
  for (const w of writes) {
    assertEquals(w.name.endsWith(":null"), false);
    assertEquals(w.name.endsWith(":undefined"), false);
  }
});

Deno.test("fetchMessage records/skips a UID absent from the folder without crashing", async () => {
  const fake = new ScriptedFetchClient({
    INBOX: [
      { uid: 101, size: sourceByteLength(PLAIN_SRC), source: PLAIN_SRC },
      { uid: 102, size: sourceByteLength(ALT_SRC), source: ALT_SRC },
    ],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();
  // 404 is not present in INBOX -- it is simply not yielded, not an error.
  const result = await model.methods.fetchMessage.execute(
    { folder: "INBOX", uids: [101, 404, 102], _client: factory },
    context,
  );
  assertEquals(result.dataHandles.length, 2);
  assertEquals(writes.length, 2);
  const names = writes.map((w) => w.name).sort();
  assertEquals(names, ["message:INBOX:101", "message:INBOX:102"]);
});

Deno.test("fetchMessage always closes the mailbox even when a fetch throws", async () => {
  const fake = new ScriptedFetchClient(
    { INBOX: [{ uid: 101, size: 10, source: PLAIN_SRC }] },
    777,
    { throwOnFetch: true },
  );
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();
  await assertRejects(
    () =>
      model.methods.fetchMessage.execute(
        { folder: "INBOX", uids: [101], _client: factory },
        context,
      ),
    Error,
    "synthetic fetch failure",
  );
  assertEquals(writes.length, 0);
  // The finally block closed the mailbox and the session still logged out.
  assertEquals(fake.closedCount, 1);
  assertEquals(fake.loggedOut, true);
  assertEquals(fake.lockCalls, 0);
});

Deno.test("fetchMessage honors the injected _parse seam and keeps attachment metadata only", async () => {
  // An edge case expressed through the parser seam rather than real MIME:
  // an html-only body with an attachment that carries a contentId.
  const stubParse: MimeParser = (_source) =>
    Promise.resolve({
      text: null,
      html: "<b>stub</b> https://example.com/seam",
      attachments: [{
        filename: "inline.bin",
        mimeType: "application/octet-stream",
        contentId: "<cid-1@example.com>",
        size: 42,
      }],
    });
  const fake = new ScriptedFetchClient({
    INBOX: [{ uid: 707, size: 20, source: "RAW-BYTES-IGNORED-BY-STUB" }],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();
  await model.methods.fetchMessage.execute(
    { folder: "INBOX", uids: [707], _client: factory, _parse: stubParse },
    context,
  );
  const d = writes[0].data as Record<string, unknown>;
  assertEquals(d.text, null);
  assertEquals(d.html, "<b>stub</b> https://example.com/seam");
  assertEquals(d.links, ["https://example.com/seam"]);
  const atts = d.attachments as Array<Record<string, unknown>>;
  assertEquals(atts[0].filename, "inline.bin");
  assertEquals(atts[0].contentType, "application/octet-stream");
  assertEquals(atts[0].size, 42);
  assertEquals(atts[0].contentId, "<cid-1@example.com>");
  assertEquals(Object.keys(atts[0]).includes("content"), false);
});

Deno.test("fetchMessage witnesses an under-cap UID whose source the server did NOT return (NF-1), distinct from over-cap withheld", async () => {
  const fake = new ScriptedFetchClient({
    INBOX: [
      // Under the cap (so requested in the source fetch) but NO source comes
      // back -- models an expunge/vanish between the size and source fetches.
      { uid: 505, size: 100, source: undefined },
      // A healthy neighbour, to prove the batch still proceeds.
      { uid: 101, size: sourceByteLength(PLAIN_SRC), source: PLAIN_SRC },
    ],
  });
  const factory: ClientFactory = () => fake;
  const { context, writes } = makeContext();
  await model.methods.fetchMessage.execute(
    { folder: "INBOX", uids: [505, 101], _client: factory },
    context,
  );
  // 505 WAS requested in the source fetch (it is under the cap).
  assertEquals(
    (sourceFetchCall(fake)?.range ?? "").split(",").includes("505"),
    true,
  );
  const missing = writes.find((w) => w.name === "message:INBOX:505")!
    .data as Record<string, unknown>;
  // Witnessed, not silent: error set, null bodies, truncated=false.
  assertEquals(missing.error, SOURCE_NOT_RETURNED);
  assertEquals(missing.text, null);
  assertEquals(missing.html, null);
  assertEquals(missing.truncated, false);
  assertEquals(missing.attachments, []);
  assertEquals(missing.links, []);
  // The healthy neighbour decoded normally.
  const ok = writes.find((w) => w.name === "message:INBOX:101")!
    .data as Record<string, unknown>;
  assertEquals(ok.error, null);
  assertEquals(typeof ok.text, "string");
});
