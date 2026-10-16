# @shrug/imap

Provider-agnostic IMAP inspection and gated-write model for swamp, built on the
`imapflow` library. It pulls a mailbox's structure, message metadata, and (on
demand) full message bodies, and -- behind a dry-run gate -- applies keyword,
move, and folder-creation changes.

It is a real typed primitive, not a shell/CLI wrapper: all IMAP traffic goes
through imapflow behind a single injectable client seam, so unit tests run
against a synthetic in-memory client and never touch a live server.

## Read methods (read-only)

Read methods open every mailbox with `readOnly: true` (IMAP EXAMINE, not
SELECT), so the server itself refuses mutation through the session.

- `listFolders` -- enumerate the folder tree (IMAP LIST) and attach each
  folder's message count and total size (IMAP STATUS). Writes a `folders`
  snapshot resource.
- `sync` -- fetch message ENVELOPES plus a fixed set of HEADERS ONLY (never
  bodies): From, To, Cc, Subject, Date, Message-ID, In-Reply-To, References,
  List-ID, List-Unsubscribe, List-Post, Reply-To, Auto-Submitted, Precedence --
  together with flags and size. Writes one `snapshot` resource per folder, each
  marked `headersOnly: true`. Fans out over multiple folders in one run.
  Arguments: `folder` (string or string array; defaults to `defaultFolder`),
  `limit` (cap the most-recent N messages per folder).
- `fetchMessage` -- the one read method that pulls FULL bodies, for a single
  folder per call (an IMAP UID is unique only within one folder + UIDVALIDITY).
  It uses a pre-fetch SIZE GATE: one `{uid, size}` fetch partitions the UID set
  against `MAX_BODY_BYTES` (1 MiB), then a single source fetch pulls only the
  under-cap UIDs -- never a per-UID loop, and an over-cap body is never
  buffered. Bodies decode with `postal-mime` into one `messageBody` record per
  UID (decoded headers, `text`/`html`, attachment METADATA ONLY, deduped
  http/https links, an `error` witness). Per-message decode is isolated so one
  malformed message cannot abort the batch. Arguments: `folder`, `uids` (array,
  capped at `MAX_FETCH_UIDS` = 25), optional `uidValidity` (fail-closed if it
  drifts). Caveats: stored `html` is UNSANITIZED (no renderer is in scope);
  `messageBody` records have a finite 30-day lifetime; over-cap messages report
  `truncated: true` with null bodies and the server-reported `sourceBytes`.

## Write methods (gated)

Every write method defaults to `dryRun: true`, which produces a would-affect
preview and mutates nothing. `dryRun: false` is the only mutating path. Writes
are UIDVALIDITY-guarded (fail-closed on drift), fan out a single STORE/MOVE per
group rather than looping per UID, and verify the result with a post-mutation
re-FETCH that surfaces any discrepancies. Mutating opens use an imapflow mailbox
lock and release (never CLOSE on a read-write box, which would implicit-expunge
`\Deleted` mail).

- `addKeywords` / `removeKeywords` -- STORE custom IMAP keywords (tags) across a
  UID set. Keyword grammar is validated (the `\`-flag namespace and non-ASCII
  are rejected).
- `move` -- MOVE a UID set to a destination folder; absent-from-source UIDs are
  reported in a distinct `missingFromSource` bucket.
- `applyTagPlan` -- read the latest `tagPlan` record from a
  `@shrug/mail-ontology` instance and apply it over the same safety core, fanned
  out by `(folder,
  keyword)` and `(folder, destination)` group.
- `createFolder` -- ensure a LIST of mailbox paths exist in one call (imapflow
  `mailboxCreate`), idempotent on `ALREADYEXISTS`, verified by a post-creation
  re-LIST. Mailbox-level, so it needs no UID/uidValidity machinery.

## Example

Snapshot a folder's headers, then pull two full bodies from it (read-only):

```
# Enumerate folders with counts/sizes
swamp behavior run @shrug/imap sync <instance> --input folder=INBOX --input limit=50

# Fetch full bodies for specific UIDs in one folder (size-gated, EXAMINE)
swamp behavior run @shrug/imap fetchMessage <instance> \
  --input folder=INBOX --input uids='[101, 102]'

# Preview a keyword tag write without mutating (dryRun defaults true)
swamp behavior run @shrug/imap addKeywords <instance> \
  --input folder=INBOX --input uids='[101]' --input keywords='["cat/finance"]'
```

## Configuration

Global arguments:

| Field           | Required | Default | Notes                                       |
| --------------- | -------- | ------- | ------------------------------------------- |
| `host`          | yes      | --      | IMAP server hostname, e.g. imap.example.com |
| `port`          | no       | `993`   | IMAP port (993 = implicit TLS)              |
| `user`          | yes      | --      | Mailbox login, e.g. user@example.com        |
| `password`      | yes      | --      | Sensitive; resolve from a vault via CEL     |
| `secure`        | no       | `true`  | Implicit TLS (true for 993)                 |
| `defaultFolder` | no       | `INBOX` | Folder scanned by `sync` with no `folder`   |

The `password` is marked sensitive and must be resolved from a swamp vault with
a CEL expression -- never inlined in the model definition:

```
password: ${{ vault.get("my-mailbox", "password") }}
```

The `password` global is the only secret; everything else (`host`, `port`,
`user`, `secure`) is plain connection configuration.
