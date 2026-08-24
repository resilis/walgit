# Production architecture charter

Status: frozen V5.4 production target. PR1 implements only the storage and
preservation gate described below. The V5.4 identity, control, event, recovery,
Cloud Core, cutover, and production-promotion contracts are future gates. They
are not implemented by PR1, and this document does not claim that WalGit is
ready for production.

## Outcome and preserved boundaries

Cloud Core will make a greenfield, zero-data hard cut from Forgejo to WalGit.
The cut requires a signed empty-state proof. `git.resilis.io` stays the public
Git origin. Existing GitHub integration, exact-commit builds, tenant isolation,
encrypted credential handling, webhook lifecycle compensation, and log
redaction stay unchanged.

Cloud Core remains the tenant, project, repository, build, credential, and
orchestration owner. WalGit owns Git protocol execution and repository control.
One versioned S3-compatible bucket is WalGit's only durable state. Local disk
and memory remain disposable caches.

Delivery is producer before consumer and pull-request only. A source pull
request image is never deployable. Cloud Core work starts only after the
required WalGit gates have merged and produced an approved, signed, immutable
production image. This charter does not authorize a merge, deployment,
production bucket access, or deletion of Forgejo data or storage.

PR1 installs protected CI and release machinery. It can publish a signed
development/main image only after the named CI workflow succeeds for that
exact protected-main commit. That artifact is supply-chain evidence, not a
production approval. No PR1 image is production-deployable.

## Gate order

1. **PR1 — storage and preservation evidence (implemented by this branch).**
   Freeze the behavior matrix. Correct S3 credential loading, declared-length
   handling, multipart bounds and cleanup, retry classification, and atomic
   conditional writes. Add protected CI and supply-chain evidence. Do not add
   a durable repository format.
2. **PR2 — identity and control (future).** Add `repo_control` v2, immutable
   identity, lifecycle, visibility, repository grants, writer fencing, finite
   quotas, capacity reservations, mutation receipts and settlement, exact
   object-version references, and bounded typed reclamation. The exact selected
   provider primitive gate must pass before PR2 merges.
3. **PR3 — events and operations (future).** Extend settled receipts with
   durable event materialization and fanout. Add exact-commit pins, recovery
   catalogs and journals, production-scale and recovery evidence, and one
   signed production candidate image.
4. **Cloud Core consumer and cutover (future).** Add the `walgit` provider by
   `EXPAND`, move all readers and writers by `SWITCH`, complete the signed
   cutover, and remove Forgejo-specific paths only in a later `CONTRACT` phase.

## PR1 binding storage contract

- The selected S3-compatible bucket is the only durable state. Local disk and
  memory are disposable caches.
- Small mutable metadata uses one atomic conditional write. A caller gets an
  explicit failure when the provider cannot enforce the requested condition.
- Large immutable data stays digest-addressed and streams through bounded
  multipart operations. The design continues to support a 64 GiB receive, a
  16 GiB LFS object, and 30 GiB or larger packs and bundles. It has no 4 GiB
  product limit.
- The AWS SDK default credential chain supplies refreshable credentials. Empty
  explicit override names leave standard AWS environment variables and
  temporary credentials under that chain. Configured custom access and secret
  variables override it only when both contain non-empty values. A configured
  custom session-token variable must also resolve. An incoherent partial
  override is a startup error. Secret values never enter logs or errors.
- Runtime multipart abort is best effort. The production bucket must configure
  `AbortIncompleteMultipartUpload` cleanup for uploads left by process death or
  provider outages.
- Endpoint, region, bucket, prefix, and path-style settings remain explicit
  deployment inputs. Memory, GCS, and standalone behavior remain supported.
- PR1 local RustFS evidence does not prove the production provider. The PR2
  provider gate below must use the exact endpoint, region, addressing mode,
  credential mode, temporary bucket, and unique prefix selected for
  production.

## Future V5.4 repository control contract

Everything in this section is frozen future scope. PR1 does not implement it.

### One repository authority

Each repository has one versioned `repo_control` v2 object. Its conditional
write is the only repository semantic commit point. V2 removes `manifest.pb`
and every other mutable authority. A policy object, settings object, bundle
list, LFS catalog, event record, capacity shard, lease, host index, or recovery
record cannot independently publish repository-visible state or authorize a
mutation.

Let `P` be the configured deployment prefix. `P` is empty or has 1–4
slash-terminated ASCII segments. Each segment has 1–63 bytes, matches
`[a-z0-9][a-z0-9._-]{0,62}`, and is not `.` or `..`. Thus `P` is at most 256
bytes and ends in `/` when non-empty. Let `C` be the canonical repository path
bytes. Define:

```text
canonical_path_digest = SHA-256(C)
routing_digest = SHA-256("walgit-repo-path-v1" || u32be(len(C)) || C)
repo_control_key = P || "v2/repositories/by-path/<routing_digest-lowerhex>/repo_control.pb"
R = P || "v2/repositories/by-id/<repository-uuid-lowerhex>/g<generation-16hex>/"
```

The public path therefore addresses `repo_control` without first knowing the
tenant, project, UUID, or generation. A direct lookup reads this exact key and
then verifies with binary equality that the stored canonical path is `C`, its
stored `canonical_path_digest` is `SHA-256(C)`, its stored `routing_digest` is
the domain-separated value above, and its stored complete control key is the
key read. It also verifies that lifecycle permits the operation. An
inconsistent stored identity or key is the bounded typed error
`PATH_IDENTITY_MISMATCH`. If the stored routing digest equals the requested
routing digest but the stored canonical bytes differ, the error is
`ROUTING_DIGEST_COLLISION`; the server does not try an alternate key.

`R` is the immutable payload root for that UUID and generation. Its closed
subkeys and leaf forms are:

| Kind | Key below `R` |
|---|---|
| Catalog page | `catalogs/<kind>/<sha256-lowerhex>.pb` |
| Receipt result | `receipts/results/<mutation-uuid-lowerhex>.pb` |
| Event result | `events/results/<event-uuid-lowerhex>.pb` |
| Event archive | `events/archive/<event-uuid-lowerhex>/<subscriber-sha256-lowerhex>.pb` |
| Checkpoint | `checkpoints/<wal-sequence-16hex>/<sha256-lowerhex>.pb` |
| Recovery object | `recovery/<recovery-uuid-lowerhex>/<kind>/<sequence-16hex>.pb` |
| Git pack | `git/packs/<sha256-lowerhex>.pack` |
| LFS object | `lfs/<sha256-lowerhex>.bin` |
| Bundle | `bundles/<sha256-lowerhex>.bundle` |
| Unpublished temporary object | `tmp/<kind>/<operation-uuid-lowerhex>/<sequence-16hex>.bin` |

Every object under `R` binds the full tenant, project, UUID, generation,
canonical path, `canonical_path_digest`, and `routing_digest`. Object-key
components are lowercase fixed-width hex for UUIDs and digests, 16-digit
lowercase hex for generations and sequence numbers, or a closed lowercase
ASCII kind token. The only kind
tokens are `pack`, `ref-delta`, `grant`, `receipt`, `event`, `event-change`,
`pin`, `git-ownership`, `lfs-ownership`, `bundle`, `recovery`, `audit`,
`reclamation`, `journal`, `mapping`, `git-pack-upload`, `lfs-upload`,
`bundle-upload`, `catalog-candidate`, and `recovery-copy`. Each leaf permits
only the tokens applicable to its row. A complete object key is at most 1,024
bytes.

Global and mutable auxiliary objects use only these keys:

| Kind | Exact key |
|---|---|
| Cutover authority | `P || "v2/control/cutover_control.pb"` |
| Immutable signed verification key ring | `P || "v2/control/key-rings/<sha256-lowerhex>.cbor"` |
| Capacity shard | `P || "v2/capacity/shards/<shard-2hex>/capacity_shard.pb"` |
| Writer lease | `P || "v2/leases/by-id/<repository-uuid-lowerhex>/g<generation-16hex>/writer_lease.pb"` |

There are exactly 256 capacity shards. The first byte of
`SHA-256(repository_uuid)` selects the two-hex-digit shard. Capacity shards and
leases are bounded mutable side state but cannot publish or authorize. The
signed key ring is immutable. `cutover_control` roots the initial ring, but a
later ring rotation does not mutate the terminal cutover state.

`host_control` is an optional derived discovery and routing index at
`P || "v2/host_control/by-path/<routing_digest-lowerhex>.pb"` and
`P || "v2/host_control/by-id/<repository-uuid-lowerhex>/g<generation-16hex>.pb"`.
It does not define repository existence, visibility, authorization, roots, or
writer ownership. A stale or missing host index can affect discovery only.
Direct repository lookup always reads the routing-digest-derived
`repo_control` key.

`repo_control` contains the complete bounded authority needed for a normal
read. Large collections use immutable catalog pages under `R`. A catalog
becomes authoritative only when an exact root is published by the
`repo_control` CAS.

Immutable payloads and candidate catalog pages can be written before the
control CAS. They remain unreachable and have no semantic effect until that
CAS publishes their exact roots. Every client and system mutator follows this
rule. There is no local fallback and no second publishing key.

### Bounded V2 schema

Every protobuf `string`, `bytes`, and `repeated` field has a machine-readable
bound annotation. Every message has a maximum encoded size. A descriptor
linter rejects an unbounded field, a missing message maximum, or a nested value
without an enforceable parent-size check. Decoders check item, count, and total
message bounds before allocation. Writers compact or reject when the first
field, count, or encoded-message limit is reached. They never truncate
authority.

| Message or object | Maximum encoded bytes |
|---|---:|
| `repo_control` or `cutover_control` | 1,048,576 |
| Capacity shard or checkpoint | 1,048,576 |
| Catalog node | 524,288 |
| Mutation receipt or result, event core, result, or archive, pin, build row, provider row, host row, recovery row, reclamation row, WAL-tail entry, bootstrap or cutover evidence row, or signed verification key ring | 65,536 |
| Capacity reservation, verification data-key row, or build-context row | 16,384 |
| Create-intent or capability `COSE_Sign1` envelope | 8,192 |
| Lease | 16,384 |
| Any other nested V2 control message | 4,096 |

The following field limits apply across the V2 schema:

| Field class | Bound |
|---|---:|
| Tenant, project, issuer, subject, audience, holder, purpose, cursor owner, and other opaque identifiers | 1–256 bytes |
| Repository, intent, token, mutation, event, reservation, recovery, operation, or bootstrap-session UUID | exactly 16 bytes; RFC 9562 UUIDv7 except a pre-existing repository UUID supplied by Cloud Core |
| Canonical repository path | 1–1,024 UTF-8 bytes |
| Object key | 1–1,024 bytes in the closed ASCII key grammar |
| `CasToken` | 1–256 opaque bytes |
| `ObjectVersionID` | 1–1,024 opaque bytes |
| SHA-256 digest | exactly 32 bytes |
| Git object ID | exactly 20 bytes for SHA-1 or 32 bytes for SHA-256 |
| Ref name or symbolic target | 1–1,024 bytes |
| Human-readable label or bounded error text | 0–1,024 UTF-8 bytes |
| Inline settings | 0–16,384 encoded bytes |
| Inline policy | 0–65,536 encoded bytes |
| Delivery or reclamation cursor | 0–4,096 bytes |
| Ed25519 signature | exactly 64 bytes |
| Content type, algorithm, state, kind, or enum text | 1–128 ASCII bytes |
| Any other protobuf string or byte field | 0–1,024 bytes |

Repeated fields have these maxima: 4,096 inline pack roots; 256 inline WAL-tail
entries; 256 direct grants; 64 dependencies per receipt; 256 inline ref changes
or superseded object-version IDs per tail entry; 4,096 inline ref changes in one
control object; 2,048 children per catalog node; 4,096 items per catalog leaf;
and 4,096 reservations per capacity shard. Any other repeated field has at most
64 items. Protobuf maps are not used in V2 persisted messages.

A verification key ring has at most 64 data keys and 16 allowed audiences per
key. A build has at most 64 named Git contexts. An event has at most 256 inline
ref changes; a typed event-change catalog replaces a larger set. The fixed
control catalog-root set has exactly these 11 optional slots: pack, grant,
receipt, event, pin, Git ownership, LFS ownership, bundle, recovery, audit, and
reclamation. Ref-delta roots are bound by their WAL-tail entries. Absence is
explicit; the schema does not use a variable or unknown root kind.

A catalog has at most four levels, 131,072 nodes, and 68,719,476,736 encoded
bytes. Every root records kind, key, `ObjectVersionID`, digest, size, depth, node
count, item count, and total encoded bytes. Per-repository catalog item maxima
are 1,000,000 packs; 4,000,000 refs; 65,536 grants; 16,384 unresolved receipts;
65,536 pending events; 1,000,000 pins; 100,000,000 Git-ownership entries;
100,000,000 LFS-ownership entries; 65,536 bundles; 100,000,000 recovery
entries; 10,000,000 audit entries; and 1,000,000 candidates in one reclamation
batch. Reaching a maximum applies bounded backpressure. It never silently drops
or replaces an item.

### Normal-read inline and catalog split

Every normal read first gets only the routing-digest-derived `repo_control`.
Control always carries identity and create binding; object format; lifecycle;
visibility; control revision and cutover generation; writer holder and epoch;
authorization epoch; quota, charged usage, and the active capacity binding;
inline settings and policy; WAL head, minimum sequence, and checkpoint root;
at most 256 WAL-tail entries; reclamation state and cursor root; the last
internal mutation ID; and a fixed set of typed catalog roots.

Up to and including 4,096 pack roots stay inline while the encoded control fits
its byte bound. Before an addition would create root 4,097 or exceed the byte
bound, one pack catalog replaces the entire inline pack list. Up to and
including 256 grants stay inline under the same rule. Before an addition would
create grant 257 or exceed the byte bound, one grant catalog replaces the
entire inline list. A WAL-tail entry contains at most 256 ref changes and
superseded version IDs; a typed ref-delta catalog replaces an entry before an
addition would exceed its count or byte limit. The full inline control contains
at most 4,096 ref changes. The writer compacts the tail before adding entry 257
and rejects the mutation if compaction cannot complete within the bounds.

Schema `oneof` fields make inline and catalog forms mutually exclusive.
Settings and policy remain inline. A cold ref read gets control and then exact
checkpoint, ref-delta, and pack catalog versions only when the requested ref
needs them. Receipt, event, pin, ownership, capacity, recovery, audit, and
reclamation catalogs are operation-specific and are not part of every normal
read.

### Identity and path

Repository identity is a UUID plus immutable generation 1. Control, create,
receipt, capacity, lease, recovery, capability, pin, event, build, cutover,
provider, and host records bind all of these values:

- opaque tenant ID;
- opaque project ID;
- repository UUID and generation;
- the exact canonical UTF-8 path bytes produced by Cloud Core;
- `canonical_path_digest = SHA-256(C)`; and
- the domain-separated `routing_digest` above.

Cloud Core is the only Unicode canonicalizer. Rust treats the supplied bytes
as opaque and compares them with binary equality. A shared adversarial corpus
proves that both implementations accept and reject the same paths. Rename,
move, path reuse, and generation change remain unsupported in the foundation.

The V2 Git transport base is `/<segment...>/<final>.git`. The exact lowercase
`.git` suffix is mandatory for smart HTTP and LFS transport and is not part of
the canonical path. A canonical path is the decoded segments joined by `/`,
without a leading or trailing slash. It has 1–8 non-empty UTF-8 segments and
1–1,024 decoded bytes. `/` is the only separator. The decoder rejects invalid
UTF-8, an encoded slash, an empty segment, `.` or `..`, NUL, ASCII control
bytes, backslash, and DEL. The final canonical segment cannot end in the
literal bytes `.git`.

Only ASCII unreserved bytes `[A-Za-z0-9._~-]` appear literally in the transport
path. Every other UTF-8 byte uses uppercase `%HH`. The server decodes exactly
once from the raw request target. It rejects invalid, lowercase, overlong, or
unnecessary escapes. Neither Cloud Core nor Rust applies case folding or
Unicode normalization at transport time. Cloud Core produces the canonical
bytes; both systems use one adversarial conformance corpus. Management and UI
routes use the fixed prefix
`/_repos/<same-encoded-canonical-path>/<closed-api-suffix>`, which keeps them
separate from Git transport routes. PR1 routes remain preserved until the
future hard cut. No V2 alias or legacy path fallback exists after `ACTIVE`.

Cloud Core enforces permanent global uniqueness on the exact canonical path
bytes, `canonical_path_digest`, and `routing_digest`, including tombstones.
Create requires unused canonical bytes, both digests, repository UUID, and
control key. A repository cannot be renamed or moved, a path cannot be reused,
and its generation cannot change. Different canonical bytes with the same raw
identity digest fail as `CANONICAL_PATH_DIGEST_COLLISION`. Different canonical
bytes with the same routing digest fail as `ROUTING_DIGEST_COLLISION`. These
errors are not aliases.

Only a signed Cloud Core create intent can create control. It binds identity,
path, object format, initial visibility, finite quota, and the initial
repository-admin grant. It also binds issuer, audience, key ID, intent ID,
issue time, and expiry. One `Create` of `repo_control` makes the candidate
`ACTIVE`. An exact replay is idempotent. A different intent or identity at the
same path fails.

### Signed create intents and capabilities

Create intents and capabilities use untagged `COSE_Sign1`. The protected header
contains only `alg = -8` (`EdDSA`) and a `kid` that is exactly 16 bytes. The
unprotected header is empty. The payload is deterministic CBOR under RFC 8949.
The verifier rejects duplicate map keys, indefinite-length items, floats,
non-shortest encodings, non-canonical map order, and trailing bytes. Identity
and path values are CBOR byte strings. Ed25519 signatures are exactly 64 bytes
and use strict RFC 8032 verification. The decoded payload is at most 7,680
bytes and is one integer-keyed map. It uses no CBOR text strings.

Both payloads use these required keys:

| Key | Type and value |
|---:|---|
| 1 | unsigned schema version, exactly `1` |
| 2 | unsigned type: `1` create intent or `2` capability |
| 3 | issuer byte string, 1–256 bytes |
| 4 | audience byte string, 1–256 bytes |
| 5 | intent or token UUIDv7, 16-byte byte string |
| 6 | issued-at, signed 64-bit Unix seconds |
| 7 | not-before, signed 64-bit Unix seconds |
| 8 | expiry, signed 64-bit Unix seconds |
| 9 | opaque tenant ID byte string, 1–256 bytes |
| 10 | opaque project ID byte string, 1–256 bytes |
| 11 | repository UUID, 16-byte byte string |
| 12 | generation, unsigned 64-bit integer; exactly `1` in this foundation |
| 13 | canonical path byte string, 1–1,024 bytes |
| 14 | canonical path digest `SHA-256(C)`, 32-byte byte string |
| 15 | unsigned 64-bit verification-ring epoch |
| 16 | verification-ring SHA-256 digest, 32-byte byte string |
| 17 | domain-separated routing digest, 32-byte byte string |

The create map also requires:

| Key | Type and value |
|---:|---|
| 20 | object format: unsigned `1` SHA-1 or `2` SHA-256 |
| 21 | visibility: unsigned `1` private, `2` internal, or `3` public |
| 22 | positive unsigned 64-bit logical quota |
| 23 | initial administrator issuer byte string, 1–256 bytes |
| 24 | initial administrator subject byte string, 1–256 bytes |
| 25 | unsigned 64-bit cutover generation |
| 26 | derived control-key byte string, 1–1,024 ASCII bytes |

The capability map also requires:

| Key | Type and value |
|---:|---|
| 30 | purpose enum |
| 31 | unsigned 64-bit authorization epoch |
| 32 | issuing control-key byte string, 1–1,024 ASCII bytes |
| 33 | issuing `ObjectVersionID` byte string, 1–1,024 bytes |
| 34 | unsigned 64-bit cutover generation |

Purpose is an unsigned enum: `1` clone-read, `2` Git-read, `3` Git-write, `4`
LFS-read, `5` LFS-finalize, `6` webhook-admin, `7` service-build, or `8`
repository-admin. Unknown keys, enum values, and missing required keys fail
closed.

The create external AAD is the exact ASCII bytes
`walgit-create-intent-v1`. The capability external AAD is the exact ASCII bytes
`walgit-capability-v1`. The normal COSE `Sig_structure` signs that external AAD,
the exact protected header bytes, and the exact payload bytes.

Intent and token IDs are RFC 9562 UUIDv7 values encoded as their raw 16 bytes.
Their embedded millisecond timestamp must be within 30 seconds of issued-at.
An exact create envelope replay is idempotent; reuse of its intent UUID with
any changed byte is a conflict. The allowed clock skew is 30 seconds. A create
intent lives at most 10 minutes and a capability at most 15 minutes. Both
require `issued_at <= not_before <= expiry`; issue time cannot be more than 30
seconds in the future. A verifier accepts time only from 30 seconds before
not-before through 30 seconds after expiry.

Cloud Core publishes a deterministic-CBOR verification key ring in untagged
`COSE_Sign1`, signed by a pinned Ed25519 root with external AAD
`walgit-verification-key-ring-v1`. Its integer-keyed payload contains schema
version at key 1, ring UUIDv7 at key 2, issued-at at key 3, prior-ring SHA-256
digest or an empty byte string at key 4, the data-key array at key 5, and a
positive unsigned 64-bit ring epoch at key 6. The array is sorted by binary
`kid` and contains at most 64 unique entries. A data key uses integer keys 1–7
for 16-byte `kid`, 32-byte public key, issuer byte string, a binary-sorted array
of at most 16 unique audience byte strings, not-before, not-after, and state.
Issuer and audience values have 1–256 bytes. Times are signed 64-bit Unix
seconds. State is `1` pending, `2` active, `3` retiring, or `4` revoked.

Cloud Core owns the current `(ring_epoch, ring_digest)` binding and distributes
it through its existing authenticated credential-configuration channel. This
contract adds no mutable object-store pointer to the ring. Every verifier checks
the root signature, hash chain, exact configured epoch and digest, and the same
epoch and digest in every create intent or capability. It has no last-known-good
fallback. Rotation publishes `PENDING` and proves that every serving instance,
writer, and other verifier loaded the exact new binding before activation. A
stale verifier leaves readiness and cannot serve or mutate. Only `ACTIVE` signs
new envelopes.
`RETIRING` verifies for at least 16 minutes after the last possible issue.
`REVOKED` stops verification immediately. An unknown key, stale ring, invalid
root signature, broken chain, wrong issuer or audience, invalid time, invalid
state, duplicate key, or unsorted array fails closed. Root-key rotation requires
its own signed cutover or deployment ceremony. Ring rotation changes credential
configuration, not repository state or terminal `cutover_control`.

### Lifecycle, visibility, and grants

Lifecycle is `ACTIVE -> DELETING -> TOMBSTONED`. `DELETING` immediately blocks
new user reads and writes and disappears from discovery. Only the fenced writer
can reclaim it. `TOMBSTONED` retains identity, generation, path, create binding,
and audit evidence. Deletion never deletes `repo_control` or makes the path
reusable.

Visibility is explicit. Repository grants use stable issuer and subject
identity, not an email display name. Reader, writer, and administrator roles
are repository-scoped. Host grants can route and serve but never mutate a
repository. Grant changes increment the authorization epoch. Every mutation
authorizes against the exact control version it later CASes and reauthorizes
after contention. A revocation that wins the CAS prevents a stale mutation
from retrying.

Configured static tokens use fixed-size prehashed values and constant-time
comparison across the full configured set. Any legacy issued-token MAC
verification stays constant-time. V2 capabilities use the signed contract
above. Effective settings and every describe or dump surface expose only an
allowlist and never serialize authentication, OAuth, broker, webhook, store, or
session secrets.

### One writer, epoch, and lease

One writer serializes every client and system mutation for a repository. The
holder and monotonic epoch live in `repo_control`. Push, ref update, LFS
finalize, policy, settings, grants, lifecycle, checkpoint, compaction, bundle
roots, follow, import, repair, pin, event, and reclamation all present the
expected control CAS token, control object version ID, holder, epoch, and
mutation ID.

A lease can improve availability and choose when to attempt takeover. It is
non-authoritative side state. Clock skew, lease expiry, or a stale heartbeat
cannot grant mutation authority. Takeover succeeds only when one control CAS
changes holder and increments the epoch. A stale holder receives `FENCED` and
cannot reacquire inside its mutation retry loop.

Serving instances are read-only. They forward the original opaque client
credential to the writer, which authenticates and authorizes it. A client
cannot assert a trusted principal header. Broker failure returns a bounded
error and never falls back to local publication.

### CAS tokens, object versions, and immutable roots

The store API uses two distinct opaque types:

- `CasToken` is valid only for the next conditional update.
- `ObjectVersionID` identifies an immutable historical object version.

Versioning is mandatory. Every durable root records key, `ObjectVersionID`,
digest, and size. Recovery and reclamation use exact-version HEAD, GET, and
delete. They never treat an ETag or `CasToken` as a historical identity.

When GCS is the selected provider, bucket Object Versioning remains enabled
and soft-delete retention is exactly zero. A nonzero soft-delete window makes
permanent `delete_version` completion and the related capacity refund
unprovable. Provider startup reads both settings and fails closed if either
condition is false. Permanent deletion requires exact-version HEAD and GET to
return typed not-found and a complete version enumeration to omit that
generation before capacity is refunded.

Ordinary request and maintenance paths cannot delete noncurrent versions. A
writer-fenced typed reclaimer can exact-version-delete a catalog-proven
unreachable version only after receipt, event, capacity, pin, recovery, and
retention obligations expire. It enumerates versions with bounded pagination
and handles delete markers explicitly. Automatic bucket lifecycle rules may
abort abandoned multipart uploads, but they cannot expire protected object
versions. KMS key retention exceeds the maximum retained object-version
horizon.

An object, version, delete-marker, or multipart enumeration requests at most
1,000 entries per provider page. One bounded invocation processes at most 1,000
pages and stores a continuation cursor of at most 4,096 bytes before it resumes.
Runtime cursors are rooted in control. Bootstrap holds exclusive IAM and cannot
enter `PREPARING` until all four enumerations return a terminal page.

### Mutation receipt and settlement

Every mutation with an external obligation creates an unresolved receipt core
before the publishing CAS. The core binds the mutation ID, mutation kind,
prior `CasToken`, prior control `ObjectVersionID` or explicit `NONE` for
Create, writer epoch, reservation ID, WAL sequence, and every immutable
dependency digest. The candidate control roots the immutable receipt catalog.

The successful control CAS decides repository state. A timeout or lost response
does not make a landed CAS fail. After the CAS, an immutable result envelope at
a deterministic mutation-ID key records the result control key,
`ObjectVersionID`, digest, and size. This envelope is proof only. It cannot
publish, authorize, charge capacity, emit an event, or change repository state.

Every later control version carries every unresolved receipt. A serialized
internal-settlement control CAS roots the exact result envelope before it
removes the unresolved core. Settlement waits until the related capacity state
is terminal and the event envelope and archive are verified. The settlement
CAS has no external obligation, creates no recursive unresolved receipt, and
records its own mutation ID in control. If its outcome is ambiguous, the writer
must resolve it with a fresh exact read before another CAS.

An event core does not contain its future result `ObjectVersionID`. A resolved
envelope supplies that value after publication. Checkpoint, compaction, and
receipt-catalog compaction cannot drop the core before the resolved envelope
and required archive exist. A bounded receipt catalog applies backpressure
before it reaches its limit.

### Finite quota, capacity, and reclamation

Repository quota is finite and positive. Logical usage charges each unique
canonical Git object's encoded bytes and each unique LFS object's bytes once.
Duplicate content does not charge twice. Derived packs, bundles, checkpoints,
temporary uploads, and recovery copies use separate system capacity. Global
allocatable capacity excludes computed system and emergency reserves.

Capacity uses a fixed, bounded set of repository-hashed shards. Shards are
idempotent, bounded, and reconciled. They are not repository authority and
cannot publish roots or authorize work. One writer means a repository has at
most one active reservation.

A reservation moves through these states:

1. `RESERVED` is provisional and can expire.
2. `COMMITTING` is non-expiring and binds the expected control `CasToken` and
   `ObjectVersionID`, writer epoch, mutation ID, kind, and exact byte count.
3. The writer publishes immutable payloads and then CASes `repo_control`.
4. `CHARGED` records the successful control publication exactly once.
5. `ABORTED` releases capacity only when durable historical proof shows that
   another mutation won and the expected CAS can no longer succeed.

A lost result after the control CAS is success. Reconciliation uses the
control receipt and exact object version to finish `CHARGED`. It resumes a
still-possible `COMMITTING` reservation and never aborts it because of a clock
or timeout. Concurrent shard reservations cannot exceed allocatable capacity.

Reclamation is typed, bounded by objects and bytes per pass, and resumable from
a control-rooted cursor. A pass exact-version-deletes at most 1,000 objects and
at most 5 TiB. It stops before either next item would exceed a limit and roots
the next cursor. Candidate classes are closed enums, never caller prefixes. The
protection closure includes current WAL roots, all immutable catalogs, LFS
ownership, pins, event and recovery catalogs, and their exact versions. Every
delete names an expected `ObjectVersionID`. Capacity refunds only after a
verified delete. Identity and control are never reclaimed.

## Future Cloud Core provider contract

Cloud Core adds provider value `walgit` without rewriting existing provider
rows in place. `EXPAND` teaches every reader and writer both representations.
`SWITCH` moves all producers and consumers to WalGit after deployed evidence.
A later `CONTRACT` removes Forgejo-specific representation only after no
supported consumer needs it.

The following operation table is the minimum preserved `VCSAdapter` surface.
Implementations preserve the current request and response fields, stable typed
and bounded errors, cancellation, idempotency, and pagination where the server
needs it.

| Operation | Preserved result and behavior |
|---|---|
| `GetRepository` | Return the current `Repository` fields after tenant, project, repository, generation, and path checks. |
| `ListRepositories` | Return a stable, bounded `[]Repository`; paginate provider reads and fail explicitly instead of silent truncation. |
| `GetBranches` | Return the bounded `[]string` branch view from one exact control version. |
| `GetCommit` | Return `Commit` for the requested exact SHA. |
| `GetBranchHead` | Resolve one branch to `Commit` from one exact control version. |
| `ParseWebhook` | Return the versioned `PushEvent` shape and reject unknown or oversized input. |
| `ValidateWebhook` | Authenticate the signature before parsing or acting on the body. |
| `CreateWebhook` / `CreateWebhookWithToken` | Preserve callback, events, active state, idempotency, and compensation. |
| `RepositoryWebhookCreator` | Return and persist the provider-assigned webhook ID. |
| `ListRepositoryWebhooks` | Return the bounded current provider webhook set. |
| `DeleteWebhook` / `DeleteWebhookWithToken` | Delete the exact provider webhook idempotently and preserve retry compensation. |

WalGit also exposes signed create and recovery, repository lookup, branch and
SHA reads, scoped capability issuance, lifecycle/delete, and per-repository
webhook administration. The EXPAND/SWITCH/CONTRACT map names every existing
Cloud Core reader and writer before implementation.

Clone-read, webhook-admin, and service-build credentials are distinct. Their
purposes are not interchangeable. Cloud Core preserves per-app webhook secrets,
provider webhook IDs, pending/active/delete/retry state, and current prepare,
commit, rollback, and compensation behavior. Secrets remain encrypted through
the existing envelope and AEAD references. Every operation checks opaque
tenant, project, repository, generation, canonical path bytes,
`canonical_path_digest`, and `routing_digest`. Errors remain bounded and never
contain credentials or remote response bodies.

## Future capabilities and read authorization

A capability uses the signed envelope above. It binds tenant, project,
repository UUID, generation, canonical path, `canonical_path_digest`,
`routing_digest`, purpose, token identity, authorization epoch, expiry,
verification-ring epoch and digest, and the issuing control key and
`ObjectVersionID`. Mutations reauthorize against the exact control version they
CAS. New reads check current control visibility, lifecycle, grants, and
authorization epoch. In-flight reads have a bounded timeout after revocation or
deletion.

WalGit does not issue presigned URLs that outlive repository authorization.
LFS upload can stream to an immutable candidate, but finalize reauthorizes and
publishes ownership through the control CAS. Service-build credentials are
separate from user and webhook credentials and enforce full scope and
cancellation checks.

## Future events, fanout, and build pins

The publishing control CAS includes a stable event core with repository UUID,
generation, WAL sequence, mutation ID, and the complete all-ref change set.
The core holds at most 256 changes inline; a larger set is complete through its
exact event-change catalog root. The later immutable result envelope adds the
successful control `ObjectVersionID`. `PushEvent` is versioned and preserves
current repository, ref, branch, before, after, commit, pusher, forced,
created, deleted, and compare semantics. Only branch events start builds. Tags
and other ref events remain observable but do not enqueue a build.

An ordered cursor controls delivery only. It never decides repository
correctness. Fresh HMAC material authenticates every retry while the stable
event ID preserves idempotency.

Cloud Core handles one delivery in one database transaction. That transaction
records an idempotent inbox row and deterministic per-ref and per-subscriber
outbox rows. Cloud Core returns 2xx and advances its cursor only after commit.
Deployment application is idempotent. Retries, crashes during fanout, and
out-of-order release cannot lose or duplicate deployment effects.

Before enqueue, a build intent pins the primary repository and every named Git
context through control. It returns pin identity, exact object version, SHA,
and expiry. The event CAS adds a reachability hold for at least the greater of
30 days and the full retry horizon. The queue carries exact SHAs, pin IDs,
object versions, and credential references for every context. There is no
branch fallback. The runner verifies every pin and SHA before use. Orphan-pin
reconciliation and LFS dependency closure are mandatory.

## Future recovery contract and fault model

Recovery restores bottom-up into new immutable target objects and catalogs. A
signed mapping records every source key and `ObjectVersionID` to its target key
and `ObjectVersionID`. Target catalogs contain no old references. Recovery
sets `FENCED` in control, verifies the complete Git, WAL, LFS, event, pin, and
catalog closure, and publishes the recovered root with one exact final control
CAS.

If control is missing, Cloud Core can authorize same-identity recovery only
with a signed recovery intent under a global fence. Recovery never invents a
new UUID, generation, tenant, project, or path. An all-version scan proves that
no restored catalog refers to an old target before the fence is removed.

The zero-acknowledged-loss claim covers corruption and logical overwrite or
delete within one correctly versioned bucket. It excludes loss of the bucket,
account, region, KMS key, or a permanently deleted object version. Those risks
require independent replication or backup and are not hidden by the RPO claim.

An RTO of four hours is valid only after exact-provider throughput and sizing
equations pass with two-times headroom. Writer scratch sizing uses fixed-thin,
index, and expanded-object peaks rather than a fixed guess.

## Future cutover state machine

### Fresh-prefix bootstrap

V2 uses a hard cut into one fresh, empty deployment prefix `P` on the exact
selected provider. It does not adopt, backfill, translate, or import
V1 `manifest.pb` repositories. No production repository data exists in `P`
before bootstrap. Old development data stays in its old prefix and is not
changed.

Exclusive IAM is a deployment-provisioning precondition, not a cutover step.
It is effective before an attempt starts and makes the bootstrap principal the
only actor that can create, update, delete, or start multipart uploads under
`P`. It denies legacy and runtime writers. The cutover controller first verifies
the deployed policy and makes no external change before `PREPARING`.

The bootstrap job verifies mandatory versioning and the configured version and
KMS retention. For GCS, it also proves that bucket Object Versioning is enabled
and soft-delete retention is zero. It then paginates to completion over current
objects, noncurrent object versions, delete markers, and incomplete multipart
uploads under `P`. Every set must be empty. The signed proof binds the provider
account, endpoint, region, bucket, prefix, addressing and credential modes,
versioning, soft-delete, and retention configuration, IAM policy digest, every
final page cursor, all four zero counts, time, job image digest, and bootstrap
session UUID.

The bootstrap principal performs the first durable write as one conditional
`Create` of `P || "v2/control/cutover_control.pb"` in `OPEN(g0)`. The object
carries the complete signed proof and its digest. A retry is valid only after
an exact read proves the same control `ObjectVersionID`, digest, and session and
a full scan finds only that one expected current version, with no noncurrent
version, delete marker, multipart upload, or other object. The CAS from `OPEN`
to `PREPARING` makes that proof authoritative before any other V2 object or
external cutover side effect is allowed.

After the `PREPARING` CAS lands, Cloud Core disables V1 auto-create, import,
publication, lookup fallback, and legacy route aliases as rooted, idempotent
steps. Before `PREPARED`, it installs runtime IAM for only the closed V2
namespaces, transfers cutover authority, revokes the bootstrap principal, and
roots those proofs. Repository creation is fenced until `ACTIVE`. Every later
repository starts as a new immutable UUID with generation 1 from a valid signed
create intent at the routing-digest-derived control key. No read, write,
recovery, or
discovery path can adopt V1 state. There is no legacy identity migration or
path-reuse exception.

### Cutover transitions

One signed `cutover_control` record is the global cutover authority. Its state
machine is:

```text
OPEN(g0) -> PREPARING(g1) -> PREPARED(g1) -> ACTIVE(g1)
                         \-> ABORTED(g1) -> PREPARING(g2)
```

`ACTIVE` is terminal. Each generation validates linearly at repository commit
and build enqueue. The CAS to `PREPARING` happens before any external side
effect. Every ingress fence, Forgejo barrier, drain, worker stop, retry stop,
credential revocation, scale, route change, and proof is idempotent. Its exact
configuration or evidence digest is rooted while state remains `PREPARING`.

Before `PREPARED`, Cloud Core verifies the signed zero-data condition, makes
the old path read-only, drains or terminates active mutations, stops workers
and retries, revokes mutation credentials, and records all high-water marks.
It scales Forgejo to zero before a second zero-session proof. Both providers
remain fenced during the route switch.

A crash in `PREPARING` or `PREPARED` deterministically resumes or reverts from
the rooted proofs. Revert restores and verifies the complete legacy route,
credentials, workers, and session state before CAS to `ABORTED`. A new attempt
uses a new generation. `ACTIVE` is the last cutover action, binds preparation,
route, workload, image, and generation digests, and has no return transition.

Forgejo databases, persistent volumes, and buckets remain intact after
`ACTIVE`. Their deletion requires separate explicit approval.

## Future production image and evidence

The production candidate is built once. Every provider, scale, recovery,
security, and cutover result binds its exact image digest. Promotion attests
that same digest without a rebuild or mutable tag. Cloud Core verifies the
signature, attestations, test identity, and digest before accepting the image.

Critical PR jobs and required status checks have a 15-minute P95 budget. Exact
provider evidence runs production-locally as parallel bounded jobs. No
provider job has a timeout above 15 minutes. The complete provider workflow,
including fail-closed cleanup, has a 30-minute budget. A 60-minute fallback is
not allowed. Linting rejects larger timeouts, and timing evidence enforces the
budgets.

The PR2 exact-provider primitive gate proves:

- objects larger than 5 GiB and the calculated 10,000-part boundary;
- concurrent conditional Create and Update and conditional multipart
  completion;
- refreshable credential rotation;
- failed and abandoned multipart cleanup;
- Range, HEAD, ETag, and explicit conditional-failure behavior;
- versioning enabled and stable `ObjectVersionID` results;
- paginated version enumeration;
- exact-version HEAD, GET, and delete;
- delete-marker behavior and cleanup isolation;
- for GCS, enabled bucket Object Versioning, zero soft-delete retention,
  fail-closed startup, and provably permanent exact-version deletion before a
  capacity refund;
- paginated empty-prefix proof across current objects, noncurrent versions,
  delete markers, and incomplete multipart uploads; and
- exclusive-IAM denial of a concurrent legacy or runtime writer during that
  proof and the conditional cutover-control Create.

The later production gate proves full-scale object counts, throughput,
retention, event replay and fanout, build pins, restore, cutover, and recovery
on the exact provider and exact production candidate digest.

## Future vertical acceptance

These scenarios are required by later gates. PR1 does not implement them.

- A raw-path conformance corpus proves exact one-time decoding, binary path
  identity, global uniqueness, routing-digest-derived control lookup,
  management-route separation, `canonical_path_digest` verification,
  independent raw and routing digest collision failures, and permanent
  tombstone path denial.
- Namespace tests prove every V2 object uses its closed physical key, every
  immutable payload binds UUID, generation, canonical path,
  `canonical_path_digest`, and `routing_digest`, and no host, capacity, lease,
  event, or recovery object can replace the routing-digest-derived control
  authority.
- Descriptor tests prove that every variable field, message, repeated field,
  and catalog has the stated numeric bound. Boundary tests prove exact
  inline-to-catalog transitions, mutually exclusive representations, bounded
  cold reads, backpressure, and compact-or-reject behavior.
- Cross-language deterministic-CBOR and COSE vectors cover create and
  capability payloads, independent keys 14 and 17, swapped or conflated digest
  rejection, every rejected encoding, UUIDv7 and time boundaries, exact replay,
  key-ring signatures, rotation, stale writers, and immediate revocation.
- A valid signed create intent creates the exact UUID, generation, path,
  canonical path digest, routing digest, visibility, quota, and initial admin
  once. Unsigned, altered, expired, cross-tenant, cross-project, and
  replay-conflict requests publish nothing.
- Every client and system mutation becomes visible only through one
  `repo_control` CAS. Mutable side state cannot publish, authorize, or replace a
  root.
- A successful CAS with a lost response, followed by another control CAS,
  retains the unresolved receipt, materializes the exact result envelope,
  settles it once, and never creates a recursive settlement receipt.
- Grant revocation racing a push has one linear winner. A stale push cannot
  reauthorize or publish after revocation.
- Writer takeover fences every former-writer surface. Lease clock skew and
  expiry alone never grant write authority.
- Exact logical quota boundaries, duplicate Git and LFS objects, shard
  contention, all reservation crash points, and verified refunds preserve
  finite capacity.
- Typed reclamation stays within object and byte budgets, resumes from its
  cursor, preserves every live root and pin, and exact-version-deletes only
  eligible versions.
- Bucket lifecycle tests prove that only abandoned multipart uploads expire
  automatically. KMS tests prove that every retained object version remains
  decryptable for its full retention horizon.
- Event tests cover lost CAS responses, post-CAS materialization, archive
  verification, fresh retry HMAC, fanout crashes before and after the Cloud
  Core transaction, and out-of-order delivery.
- Build tests move the primary branch and every named Git context after
  enqueue. The runner still consumes only the queued exact SHAs and verified
  pins, including their LFS closure.
- Recovery tests restore from every journal phase, prove no old references,
  recover missing control only under the signed global fence, and reject faults
  outside the stated one-bucket loss model.
- Cutover tests include open Forgejo sessions, worker and retry activity,
  crashes at every state and external step, verified abort restoration, stale
  generation requests, and terminal `ACTIVE` behavior.
- Bootstrap tests prove a fresh prefix has zero current objects, noncurrent
  versions, delete markers, and incomplete multipart uploads under exclusive
  IAM. They cover every scan and Create crash point, reject any V1 object or
  concurrent writer, and prove that no post-`ACTIVE` path adopts V1 state.
- Secret and revocation tests cover Git, LFS, API, settings, policy, webhook,
  build, and capability surfaces.
- Exact-provider tests bind the selected endpoint and candidate digest and
  exercise every PR2 primitive plus the later scale and recovery gates.
- Promotion tests prove that production consumes the exact candidate digest
  that passed all evidence, with no rebuild or mutable-tag substitution.
