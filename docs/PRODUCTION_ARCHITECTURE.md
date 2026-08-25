# Production architecture charter

Status: frozen V5.9 production target. PR1 implements only the storage and
preservation gate described below. The V5.9 identity, control, event, recovery,
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
   S3-compatible provider primitive gate must pass before PR2 merges.
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
  deployment inputs. Memory, GCS, and standalone behavior remain supported for
  development and non-production contracts. Only an S3-compatible provider is
  eligible for the future production hard cut.
- PR1 local RustFS evidence does not prove the production provider. The PR2
  provider gate below must use the exact S3-compatible endpoint, region,
  addressing mode, credential mode, temporary bucket, and unique prefix
  selected for production.

## Future V5.9 repository control contract

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

Every V2 key in this contract is the full physical provider key and therefore
includes `P` exactly once. The configured `ObjectStore` is already scoped to
`P`; its methods accept a validated store-relative suffix `S`, and the provider
sees `P || S`. The V2 adapter is the only translation boundary. It accepts a
full V2 key `K`, verifies the closed grammar and exact configured prefix,
proves `K = P || S`, strips `P` exactly once, and passes only `S` to the
configured store. For metadata, exact-version, and listing results, the adapter
prepends `P` exactly once before returning the full key to V2 semantic code.
This rule also applies when `P` is empty.

A prefix mismatch is `KEY_PREFIX_MISMATCH` and fails closed. No V2 caller
passes a full `K` directly to the already-prefixed store, treats a
store-relative suffix as an authoritative key, or concatenates `P` a second
time. In particular, `P || P || S` is never valid. Every lookup, parent root,
persisted key field, digest preimage that includes a key, and returned object
identity uses the full physical key `K`; only the configured store call uses
the relative suffix `S`.

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
| Pack catalog page | `catalogs/pack/<sha256-lowerhex>.pb` |
| Ref-delta catalog page | `catalogs/ref-delta/<sha256-lowerhex>.pb` |
| Grant catalog page | `catalogs/grant/<sha256-lowerhex>.pb` |
| Receipt catalog page | `catalogs/receipt/<sha256-lowerhex>.pb` |
| Event catalog page | `catalogs/event/<sha256-lowerhex>.pb` |
| Pin catalog page | `catalogs/pin/<sha256-lowerhex>.pb` |
| Git-ownership catalog page | `catalogs/git-ownership/<sha256-lowerhex>.pb` |
| LFS-ownership catalog page | `catalogs/lfs-ownership/<sha256-lowerhex>.pb` |
| Bundle catalog page | `catalogs/bundle/<sha256-lowerhex>.pb` |
| Recovery catalog page | `catalogs/recovery/<sha256-lowerhex>.pb` |
| Audit catalog page | `catalogs/audit/<sha256-lowerhex>.pb` |
| Reclamation catalog page | `catalogs/reclamation/<sha256-lowerhex>.pb` |
| Receipt result | `receipts/results/<mutation-uuid-lowerhex>.pb` |
| Event result | `events/results/<event-uuid-lowerhex>.pb` |
| Event archive | `events/archive/<event-uuid-lowerhex>/<subscriber-sha256-lowerhex>.pb` |
| Event archive watermark | `events/watermarks/<wal-sequence-16hex>/<sha256-lowerhex>.pb` |
| Checkpoint | `checkpoints/<wal-sequence-16hex>/<sha256-lowerhex>.pb` |
| Recovery journal | `recovery/<recovery-uuid-lowerhex>/journal/<sequence-16hex>.pb` |
| Recovery mapping | `recovery/<recovery-uuid-lowerhex>/mapping/<sequence-16hex>.pb` |
| Recovery catalog | `recovery/<recovery-uuid-lowerhex>/catalog/<sequence-16hex>.pb` |
| Recovery payload reference | `recovery/<recovery-uuid-lowerhex>/payload/<sequence-16hex>.pb` |
| Git pack | `git/packs/<sha256-lowerhex>.pack` |
| LFS object | `lfs/<sha256-lowerhex>.bin` |
| Bundle | `bundles/<sha256-lowerhex>.bundle` |
| Temporary Git pack upload | `tmp/git-pack-upload/<operation-uuid-lowerhex>/<sequence-16hex>.bin` |
| Temporary LFS upload | `tmp/lfs-upload/<operation-uuid-lowerhex>/<sequence-16hex>.bin` |
| Temporary bundle upload | `tmp/bundle-upload/<operation-uuid-lowerhex>/<sequence-16hex>.bin` |
| Temporary catalog candidate | `tmp/catalog-candidate/<operation-uuid-lowerhex>/<sequence-16hex>.pb` |
| Temporary recovery copy | `tmp/recovery-copy/<operation-uuid-lowerhex>/<sequence-16hex>.bin` |

This table is exhaustive. No other leaf or caller-supplied kind is valid.
Object-key components use lowercase fixed-width hex for UUIDs and digests and
16-digit lowercase hex for generations and sequence numbers. A complete object
key is at most 1,024 bytes.

Every persisted immutable body binds tenant, project, repository UUID,
generation, canonical path, `canonical_path_digest`, `routing_digest`, and its
semantic content. It does not bind its own key, `ObjectVersionID`, digest, or
size because those values do not exist until the store accepts the object. Only
an authoritative parent reference binds a target's exact key,
`ObjectVersionID`, digest, and size. `repo_control` roots top-level catalogs and
checkpoints. Each catalog parent roots its children. A settlement control CAS
roots a result envelope. An archive watermark roots subscriber archives. The
global recovery authority and repository control root recovery artifacts.

Raw Git pack, LFS, and bundle bytes remain their standard formats and do not
embed WalGit identity. Their exact authoritative parent references carry the
identity plus key, `ObjectVersionID`, digest, and size. Unpublished raw
temporary bytes also carry no authority.

Each digest has one exact preimage:

- a `.pb` object uses `SHA-256` over the exact stored deterministic protobuf
  wire bytes;
- a Git pack, LFS object, bundle, or raw temporary payload uses `SHA-256` over
  the exact stored raw bytes;
- any signed envelope uses `SHA-256` over the complete exact untagged
  `COSE_Sign1` bytes, including protected header, payload, and signature; and
- a verification-ring key uses the digest of the exact stored untagged
  verification-ring `COSE_Sign1` bytes.

These are object and envelope identity digests. The credential verifier-set and
acknowledgement-set semantic fields below use their separately domain-separated
digest formulas; neither retained evidence value is a bucket object identity.

Readers hash the stored bytes before parsing and reject a non-matching digest.
Persisted protobuf uses deterministic field ordering, minimal varints, packed
canonical repeated scalars, no maps, no unknown fields, no duplicate singular
fields, and no groups. The subscriber component is
`SHA-256("walgit-subscriber-v1" || u32be(len(subscriber_id)) || subscriber_id)`.

Global control-plane objects use only these keys:

| Kind | Exact key |
|---|---|
| Cutover authority | `P || "v2/control/cutover_control.pb"` |
| Credential binding authority | `P || "v2/control/credential_control.pb"` |
| Bucket-administration safety authority | `P || "v2/control/bucket_admin_control.pb"` |
| Immutable signed verification key ring | `P || "v2/control/key-rings/<sha256-lowerhex>.cose"` |
| Capacity allocation authority | `P || "v2/capacity/capacity_control.pb"` |
| Immutable tenant-capacity catalog page | `P || "v2/capacity/catalogs/tenant/<sha256-lowerhex>.pb"` |
| Capacity shard | `P || "v2/capacity/shards/<shard-2hex>/capacity_shard.pb"` |
| Global recovery authority | `P || "v2/recovery/recovery_control.pb"` |
| Writer lease | `P || "v2/leases/by-id/<repository-uuid-lowerhex>/g<generation-16hex>/writer_lease.pb"` |
| Host index by path | `P || "v2/host_control/by-path/<routing_digest-lowerhex>.pb"` |
| Host index by identity | `P || "v2/host_control/by-id/<repository-uuid-lowerhex>/g<generation-16hex>.pb"` |

There are exactly 256 capacity shards. The first byte of
`SHA-256(repository_uuid)` selects the two-hex-digit shard. `capacity_control`
is the CAS-owned allocation authority. Capacity shards and leases are bounded
mutable side state but cannot publish or authorize. `recovery_control` is the
global recovery fence; it cannot publish repository state. The signed key
rings and tenant-capacity catalog pages are
immutable. Their authoritative controls bind exact roots. `credential_control`
selects the bounded accepted ring set. `cutover_control` roots its initial
control-plane graph, but later credential, capacity, bucket-safety, or recovery
changes do not mutate the terminal cutover state.

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
| `capacity_control`, its redistribution state payload, capacity shard, or checkpoint | 1,048,576 |
| `credential_control`, `bucket_admin_control`, or `recovery_control` | 65,536 |
| Catalog node | 524,288 |
| Event archive watermark | 524,288 |
| Mutation receipt or result, event core, result, archive, pin, build row, provider row, host row, recovery row, reclamation row, WAL-tail entry, bootstrap, cutover, bucket-safety evidence row, signed cutover-proof envelope, or signed verification key ring | 65,536 |
| Signed credential verifier-set envelope or credential acknowledgement-set bytes | 65,536 |
| Archive-root reference | 4,096 |
| Capacity reservation, tenant-capacity allocation row, verification data-key row, or build-context row | 16,384 |
| Create-intent, capability, or credential-transition-proof `COSE_Sign1` envelope | 8,192 |
| Lease | 16,384 |
| Any other nested V2 control message | 4,096 |

The following field limits apply across the V2 schema:

| Field class | Bound |
|---|---:|
| Tenant, project, issuer, subject, audience, holder, purpose, cursor owner, and other opaque identifiers | 1–256 bytes |
| Repository, intent, token, proof, mutation, event, reservation, recovery, operation, or bootstrap-session UUID | exactly 16 bytes; RFC 9562 UUIDv7 except a pre-existing repository UUID supplied by Cloud Core |
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
| S3 proof key, version-ID, or upload-ID marker | 0–1,024 bytes |
| Canonical S3 proof cursor | 39–2,087 bytes |
| Cutover scan record | computed maximum 4,404 bytes; hard cap 8,192 bytes |
| Bootstrap-proof IAM revision or request watermark | 1–4,096 bytes |
| Ed25519 public key | exactly 32 bytes |
| Ed25519 signature | exactly 64 bytes |
| HMAC-SHA256 key ID or event-delivery key ID | exactly 16 bytes |
| HMAC-SHA256 result or body digest | exactly 32 bytes |
| HTTPS callback URL or normalized callback path | 1–2,048 ASCII bytes |
| Webhook body | 1–1,048,576 bytes |
| Provider admission horizon | 0–300 seconds |
| Event-to-READY interval, named `event_to_build_intent_delay` | 0–2,592,000 seconds |
| Build queue, retry, or maximum completion horizon | 0–2,592,000 seconds each; their sum is at most 7,776,000 seconds |
| Conservative event build-retention span | 0–10,368,000 seconds |
| Content type, algorithm, state, kind, or enum text | 1–128 ASCII bytes |
| Any other protobuf string or byte field | 0–1,024 bytes |

Repeated fields have these maxima: 4,096 inline pack roots; 256 inline WAL-tail
entries; 256 direct grants; 64 immutable dependencies per receipt; 256 ref
changes or superseded object-version IDs per tail entry; 4,096 aggregate inline
ref changes across all WAL-tail entries in one control object; exactly 256
shard-budget rows per `capacity_control`; exactly 256 target shard budgets and,
in `APPLYING`, exactly 256 drained-shard baselines; exactly 256 shard slices per
tenant-capacity row; at most 262 bootstrap creation-plan rows per cutover
generation; 2,048 children per catalog node; 4,096 items per catalog leaf;
4,096 reservations per capacity shard; and 4,096 current tenant-account rows
per capacity shard. Any other repeated field has at most 64 items. The
credential binding has exactly one current and at most one next and one previous
root, at most 64 revoked key IDs, and no other ring slot. A webhook has exactly
one current and at most one previous HMAC-key reference. Protobuf maps are not
used in V2 persisted messages. A repository has at most 64 active webhook
subscribers. An archive watermark has at most 64 archive-root references, and
each reference has a maximum encoded size of 4,096 bytes. The descriptor
linter computes the maximum outer encoding from the repeated count, nested
message bounds, tags, lengths, and fixed fields and proves that it fits the
524,288-byte watermark limit.

A verification key ring has at most 64 data keys and 16 allowed audiences per
key. A build has at most 64 named Git contexts. One atomic ref transaction and
its event core have at most 256 inline ref changes and have no overflow
representation. The 4,096 control-wide limit above bounds aggregate historical
WAL-tail state and never permits an atomic transaction above 256. The fixed control
catalog-root set has exactly these 11 optional slots: pack, grant,
receipt, event, pin, Git ownership, LFS ownership, bundle, recovery, audit, and
reclamation. Ref-delta roots are bound by their WAL-tail entries. Absence is
explicit; the schema does not use a variable or unknown root kind.

A catalog has at most four levels, 131,072 nodes, and 68,719,476,736 encoded
bytes. Every root records kind, key, `ObjectVersionID`, digest, size, depth, node
count, item count, and total encoded bytes. Per-repository catalog item maxima
are 1,000,000 packs; 4,000,000 refs; 65,536 grants; 16,384 retained receipt
rows in the future multilevel model (with at most one `UNRESOLVED` row);
65,536 pending events; 1,000,000 pins; 100,000,000 Git-ownership entries;
100,000,000 LFS-ownership entries; 65,536 bundles; 100,000,000 recovery
entries; 10,000,000 audit entries; and 1,000,000 candidates in one reclamation
batch. Reaching a maximum applies bounded backpressure. It never silently drops
or replaces an item. The dormant flat-catalog slice has the lower explicit
limit of 4,096 retained rows and does not implement multilevel compaction.

The dormant global tenant-capacity catalog is one immutable flat page with at
most 4,096 binary-sorted unique allocation rows and at most 524,288 exact
encoded bytes. Either bound can apply first and causes explicit backpressure.
Each row binds one opaque tenant ID, a finite total tenant budget, and exactly
256 positive per-shard slices whose checked sum equals that budget. Before
activation, a later explicit schema and controller phase must introduce the
deferred multilevel topology and its 65,536-row target. For each shard column,
the checked sum of all tenants' slices must be no greater than that shard's
budget, and the checked aggregate must be no greater than the plan's global
allocatable bytes. The exported cross-object validator exact-binds loaded page
bytes to the control root and proves these sums for the current plan and, while
PREPARING, the target plan. A page reference alone cannot prove the referenced
body, so the future controller must run that validator immediately after exact
strict loads and before publishing a plan or admitting a reservation.

### Normal-read inline and catalog split

Every normal read first gets only the routing-digest-derived `repo_control`.
Control always carries identity and create binding; object format; lifecycle;
visibility; control revision and cutover generation; writer holder and epoch;
authorization epoch; quota, charged usage, and the active capacity binding;
bucket-admin epoch and safety digest; inline settings and policy; WAL head,
minimum sequence, and checkpoint root; at most 256 WAL-tail entries;
reclamation state and cursor root; the last internal mutation ID; and a fixed
set of typed catalog roots.

Up to and including 4,096 pack roots stay inline while the encoded control fits
its byte bound. Before an addition would create root 4,097 or exceed the byte
bound, one pack catalog replaces the entire inline pack list. Up to and
including 256 grants stay inline under the same rule. Before an addition would
create grant 257 or exceed the byte bound, one grant catalog replaces the
entire inline list. A WAL-tail entry contains at most 256 ref changes and
superseded version IDs; a typed ref-delta catalog replaces an entry before an
addition would exceed its count or byte limit. The full inline control contains
at most 4,096 aggregate historical ref changes across its WAL-tail entries;
this does not raise the 256-change limit for one atomic transaction. The writer
compacts the tail before adding entry 257 and rejects the mutation if compaction
cannot complete within the bounds.

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
`ACTIVE`. At that same derived `repo_control` key, an exact replay is idempotent
and a different intent or identity fails.

### Signed create intents and capabilities

Create intents and capabilities use untagged `COSE_Sign1`. Their protected
header is the exact deterministic-CBOR map `{1: -8, 4: data_kid}`, where
`data_kid` is exactly 16 bytes. Their unprotected header is the exact empty map.
The payload is deterministic CBOR under RFC 8949. The verifier rejects
duplicate map keys, indefinite-length items, floats, non-shortest encodings,
non-canonical map order, and trailing bytes. Identity and path values are CBOR
byte strings. Ed25519 signatures are exactly 64 bytes and use strict RFC 8032
verification. The decoded payload is at most 7,680 bytes and is one
integer-keyed map. It uses no CBOR text strings.

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
| 35 | repository-grant issuer byte string, 1–256 bytes |
| 36 | repository-grant subject byte string, 1–256 bytes |

Purpose is an unsigned enum: `1` clone-read, `2` Git-read, `3` Git-write, `4`
LFS-read, `5` LFS-finalize, `6` webhook-admin, `7` service-build, or `8`
repository-admin. Unknown keys, enum values, and missing required keys fail
closed. Key 3 identifies the capability signer. Keys 35 and 36 identify the
exact repository grant and are independent of key 3. Binary equality is
required; a verifier does not derive either grant identity from an email,
display name, signer, token holder, or request path.

Every capability-authorized read or mutation rereads the current
`repo_control`, finds the exact `(grant issuer, grant subject)` pair, checks its
role and the capability authorization epoch, and then applies lifecycle,
visibility, and purpose rules. Clone-read, Git-read, LFS-read, and service-build
require reader, writer, or administrator. Git-write and LFS-finalize require
writer or administrator. Webhook-admin and repository-admin require
administrator. A mutation repeats this grant check against the exact control
version it will CAS, including after CAS contention. A missing, revoked,
wrong-role, or changed grant fails closed.

The create external AAD is the exact ASCII bytes
`walgit-create-intent-v1`. The capability external AAD is the exact ASCII bytes
`walgit-capability-v1`. The normal COSE `Sig_structure` signs that external AAD,
the exact protected header bytes, and the exact payload bytes.

Every `COSE_Sign1` in this credential contract uses an attached, non-null
byte-string payload. Detached and CBOR-null payloads fail closed. Data-key and
acknowledgement `kid` values are opaque reserved 16-byte values; a verifier
derives only `root_kid` from a public key.

Intent and token IDs are RFC 9562 UUIDv7 values encoded as their raw 16 bytes.
Their embedded millisecond timestamp must be within 30 seconds of issued-at.
At the same derived `repo_control` key, an exact create envelope replay is
idempotent; reuse of its intent UUID with any changed byte is a conflict. WalGit
does not create, query, or LIST a global intent-ID index. Before signing, Cloud
Core atomically records and permanently enforces uniqueness of every
create-intent UUID across all tenants, projects, paths, and repository UUIDs. A
valid signature is the producer assertion that this reservation completed;
this does not create a second global bucket authority. The allowed clock skew
is 30 seconds. A create intent
lives at most 10 minutes and a capability at most 15 minutes. Both require
`issued_at <= not_before <= expiry`; issue time cannot be more than 30 seconds
in the future. A verifier accepts time only from 30 seconds before not-before
through 30 seconds after expiry.

The lifetime calculation is checked `expiry - issued_at`: at most 600 seconds
for a create intent or transition proof and 900 seconds for a capability.
Envelope validity uses the verifier's explicit `now` and only the stated
30-second envelope skew. A data key requires `not_before <= not_after`; key
eligibility is evaluated at the signed envelope `issued_at` with no key skew.
These are separate checks, so a correctly issued envelope can remain valid
while a previous ring drains. Ring and verifier-set IDs need valid UUIDv7 wire
form only. They have no UUID-to-issued-at proximity, artifact lifetime, or
future-skew rule beyond the requirements stated for their containing object.

Cloud Core publishes a deterministic-CBOR verification key ring in untagged
`COSE_Sign1`, signed by a pinned Ed25519 root with external AAD equal to the
exact ASCII bytes `walgit-verification-key-ring-v1`. Let `root_public_key` be
the exact 32-byte pinned Ed25519 public key and define
`root_kid = first16(SHA-256("walgit-ed25519-root-kid-v1" || root_public_key))`.
Here `first16` means the first 16 digest bytes in wire order. The production
candidate and `cutover_control` pin both exact values. The ring
protected header is the exact deterministic-CBOR map `{1: -8, 4: root_kid}`;
its unprotected header is the exact empty map. Its integer-keyed payload
contains schema version exactly `1` at key 1, ring UUIDv7 at key 2, issued-at at
key 3, prior-ring SHA-256 digest at key 4, the data-key array at key 5, and a
positive unsigned 64-bit ring epoch at key 6. Key 4 is an empty byte string only
for the bootstrap ring and otherwise is exactly 32 bytes. The array is sorted
by binary `kid` and contains 1–64 unique entries. A data key uses integer keys
1–7 for 16-byte `kid`, 32-byte public key, issuer byte string, a binary-sorted
array of at most 16 unique audience byte strings, not-before, not-after, and
state. Issuer and audience values have 1–256 bytes. Times are signed 64-bit
Unix seconds. State is `1` PENDING, `2` ACTIVE, `3` RETIRING, or `4` REVOKED.

The bootstrap `CredentialControl` has schema version `2`, control revision `1`,
issuer epoch `1`, exactly the bootstrap ring root in `current`, absent `next`
and `previous`, absent `previous_last_issue_unix_seconds`, and an empty
`revoked_kids` list. The bootstrap ring has ring epoch `1`, an empty prior-ring
digest, and at least one `ACTIVE` data key. Its verifier-set and
acknowledgement-proof digests come from the bootstrap transition proof below.
No other bootstrap value is valid.

For every later install, checked addition must prove
`next.ring_epoch = current.ring_epoch + 1`; `current.ring_epoch = u64::MAX`
therefore makes another install impossible. The next ring payload key 6 must
equal that epoch, and payload key 4 must equal the exact `current.digest`. The
next root's full key, `ObjectVersionID`, digest, size, and epoch must match that
payload and immutable object. A skipped epoch, zero or wrapped epoch, empty or
wrong prior digest, rollback, or a candidate fork from any root other than the
currently bound `current` fails closed. If two candidates fork from one
current, only one install CAS can land; the loser can never become `next` after
the winner changes current lineage.

Cloud Core permanently reserves each ring UUIDv7, data `kid`, and Ed25519
public-key byte string before signing a ring. It never reuses one in another
ring, including after retirement or revocation. The root signature is the
producer assertion that those reservations completed; WalGit creates no global
bucket index. WalGit additionally rejects a next ring whose UUID, root tuple,
`kid`, or public key duplicates any bound current, next, or previous ring, or
whose `kid` occurs in `revoked_kids`. Because epoch and prior digest are inside
the signed bytes and the object key is their digest, a valid descendant cannot
reuse an older ring body or root identity. Digest collision, duplicate root,
reused identity, and retired-key reuse all fail closed.

Slot position and key state jointly decide use:

| Data-key state | `current` slot | `next` slot | `previous` slot |
|---|---|---|---|
| `PENDING` | no sign; no verify | no sign; no verify | no sign; no verify |
| `ACTIVE` | sign and verify | verify only | verify only |
| `RETIRING` | verify only | no sign; no verify | verify only |
| `REVOKED` | no sign; no verify | no sign; no verify | no sign; no verify |

Only an `ACTIVE` key in the bound `current` ring can sign. The immutable ring
placed in `next` already marks the key that will be promoted as `ACTIVE`, but
slot position prevents issuance until the promotion CAS. `PENDING` and
`REVOKED` never sign or verify. `RETIRING` never signs and verifies only in an
allowed `current` or `previous` slot. The global revoked-`kid` set overrides
the matrix.

The credential authority uses these exact protobuf fields and tags. The shown
scalar types are the wire types. The message fields have protobuf presence;
`previous_last_issue_unix_seconds` uses explicit optional presence so Unix
second zero is distinct from absence.

```proto
message VerificationRingRoot {            // maximum 4,096 encoded bytes
  bytes key = 1;                           // 1..1,024 bytes
  bytes object_version_id = 2;             // 1..1,024 bytes
  bytes digest = 3;                        // exactly 32 bytes
  uint64 size = 4;                         // 1..65,536
  uint64 ring_epoch = 5;                   // positive
}

message CredentialControl {               // maximum 65,536 encoded bytes
  uint32 schema_version = 1;               // exactly 2
  uint64 control_revision = 2;             // positive
  uint64 issuer_epoch = 3;                 // positive
  VerificationRingRoot current = 4;        // exactly one
  VerificationRingRoot next = 5;           // zero or one
  VerificationRingRoot previous = 6;       // zero or one
  optional int64 previous_last_issue_unix_seconds = 7;
  repeated bytes revoked_kids = 8;          // 0..64; each exactly 16 bytes
  bytes verifier_set_digest = 9;            // exactly 32 bytes
  bytes acknowledgement_proof_digest = 10; // exactly 32 bytes
}
```

`current` is present exactly once. `next` and `previous` are independently
optional and cannot occur more than once. The previous-last-issue field is
present if and only if `previous` is present. `revoked_kids` is binary-sorted,
unique, and has at most 64 entries. `verifier_set_digest` is the
domain-separated digest of the exact signed verifier-set envelope defined
below. `acknowledgement_proof_digest` is the SHA-256 digest of the exact
untagged credential-transition `COSE_Sign1` bytes defined below. Both fields
are always present. Duplicate singular fields, unknown fields, alternate tags,
and non-canonical encodings fail before generated decoding.

Every `VerificationRingRoot.key` is the full physical key
`P || "v2/control/key-rings/<digest-lowerhex>.cose"`; the leaf digest equals the
root's `digest`. Exact-version GET and HEAD must return the same full key,
`ObjectVersionID`, body digest, and size, and the verified ring payload epoch
must equal `ring_epoch`. A root with a zero size or epoch, a mismatched key,
metadata, body, or epoch, pairwise-equal slot roots, or duplicate slot epochs
fails closed. A verifier accepts a ring only when this complete five-field root
equals one explicitly bound slot. It never follows an unbound ring or falls
back to a cached binding.

Every successful credential-control CAS increments `control_revision` by
exactly one. `issuer_epoch` never decreases and increments by exactly one when
a promotion changes the signing ring or when the deny set grows. Installing
`next` does not change `issuer_epoch`. The deny set is binary-sorted,
append-only, and permanent for schema version 2. Retirement adds every `kid`
from `previous` that is not already present, then removes `previous` and its
last issue time in the same CAS. Before installing `next`, the controller proves
that eventual retirement of current would keep this union at or below 64. If
the bound cannot hold, rotation fails closed and requires a later root-key or
schema ceremony; it never drops history. Preload installs only `next`.
Promotion requires `next` and an empty `previous` slot, moves `next` to
`current`, moves the old `current` to `previous`, clears `next`, and records the
last issue time for the old current ring in the same CAS. No other slot
transition is valid.

Tags 1–10 and their meanings, wire types, bounds, presence, and cardinality are
permanent for schema version 2. A tag is never reused, and a writer never emits
an unknown field. An incompatible change requires a new schema and object
contract introduced through `EXPAND`, `SWITCH`, and later `CONTRACT`; readers
do not accept an alias, dual encoding, or mixed interpretation.

#### Credential verifier and acknowledgement sets

The credential verifier set is an untagged `COSE_Sign1` signed by the same
pinned Ed25519 root that signs verification rings. Its protected header is the
exact deterministic-CBOR map `{1: -8, 4: root_kid}`, its unprotected header is
the exact empty map, and its external AAD is the exact ASCII bytes
`walgit-credential-verifier-set-v1`. The decoded deterministic-CBOR payload has
a maximum of 65,024 bytes, contains no text strings, and uses exactly these
numeric keys:

| Key | Exact value |
|---:|---|
| 1 | unsigned schema version, exactly `1` |
| 2 | verifier-set UUIDv7, 16-byte byte string |
| 3 | issued-at, signed 64-bit Unix seconds |
| 4 | positive unsigned 64-bit verifier-set epoch |
| 5 | array of 1–64 verifier-member maps |

A verifier-member map has exactly these numeric keys:

| Key | Exact value |
|---:|---|
| 1 | opaque member ID byte string, 1–256 bytes |
| 2 | unsigned role bit mask, 1–15: bit 0 serving instance, bit 1 writer, bit 2 issuer, bit 3 verifier |
| 3 | acknowledgement `kid`, 16-byte byte string |
| 4 | Ed25519 acknowledgement public key, 32-byte byte string |
| 5 | positive unsigned 64-bit membership epoch |

Members sort first by raw member-ID bytes in lexicographic order, then by
unsigned membership epoch in ascending numeric order, then by raw
acknowledgement-`kid` bytes in lexicographic order. Member IDs and
acknowledgement `kid` values are independently unique; duplicate public keys
are invalid. Unknown keys, zero or unknown role bits, empty members, and
non-canonical CBOR fail closed. The root uses strict RFC 8032 verification.
Cloud Core permanently reserves the set UUID and member acknowledgement
identities before signing. The bootstrap set epoch is exactly `1`. A
verifier-set-update uses checked current epoch plus one and a new set UUID;
every other transition retains the predecessor set bytes and digest. Rollback,
skip, wrap, fork publication, UUID reuse, or a same-epoch changed set fails
closed. Define the semantic digest:

```text
verifier_set_digest =
  SHA-256("walgit-credential-verifier-set-digest-v1" ||
          u32be(len(exact_untagged_verifier_set_COSE_Sign1_bytes)) ||
          exact_untagged_verifier_set_COSE_Sign1_bytes)
```

The credential acknowledgement set is one deterministic-CBOR map with a
maximum of 65,536 bytes and exactly these numeric keys:

| Key | Presence and exact value |
|---:|---|
| 1 | required unsigned schema version, exactly `1` |
| 2 | required `verifier_set_digest`, 32-byte byte string |
| 3 | required `transition_projection_digest`, 32-byte byte string |
| 4 | required unsigned transition kind, exactly the proof key 3 value |
| 5 | required unsigned binding kind: `1` bootstrap or `2` predecessor |
| 6 | bootstrap only: bootstrap-session UUIDv7, 16-byte byte string |
| 7 | predecessor only: full physical credential-control key, 1–1,024 ASCII bytes |
| 8 | predecessor only: `ObjectVersionID`, 1–1,024 bytes |
| 9 | predecessor only: exact-body SHA-256 digest, 32 bytes |
| 10 | predecessor only: exact-body size, unsigned 1–65,536 |
| 11 | required array of 1–64 acknowledgement-member maps |

An acknowledgement-member map has exactly these numeric keys:

| Key | Presence and exact value |
|---:|---|
| 1 | required member ID byte string, 1–256 bytes |
| 2 | required positive unsigned 64-bit membership epoch |
| 3 | required unsigned role bit mask, 1–15 |
| 4 | required acknowledgement time, signed 64-bit Unix seconds |
| 5 | promote-next issuer only: last issued-at, signed 64-bit Unix seconds |
| 6 | required strict Ed25519 signature, 64-byte byte string |

The acknowledgement rows have exactly the verifier-set member count and the
same order. Their member ID, membership epoch, and role mask equal the matching
verifier member. Key 5 is present if and only if the transition is promote-next
and the role mask contains the issuer bit. It is not later than key 4. For an
issuer that emitted no envelope, key 5 is the current ring issued-at value.
Binding kind `1` is valid only for transition kind bootstrap, requires key 6,
and rejects keys 7–10. Binding kind `2` is required for every other transition,
requires keys 7–10, and rejects key 6.

Let `acknowledgement_binding_bytes` be the exact deterministic-CBOR encoding of
acknowledgement-set keys 1–10, omitting key 11. Let
`unsigned_acknowledgement_member_bytes` be the exact deterministic-CBOR encoding
of that member's keys 1–5, omitting key 6. Each member signature uses its bound
acknowledgement public key and strict RFC 8032 over these exact bytes:

```text
"walgit-credential-member-ack-v1" ||
u32be(len(acknowledgement_binding_bytes)) || acknowledgement_binding_bytes ||
u32be(len(unsigned_acknowledgement_member_bytes)) ||
unsigned_acknowledgement_member_bytes
```

Every signature must verify. Unknown, missing, duplicate, extra, reordered, or
wrong-member rows fail closed. Define:

```text
acknowledgement_set_digest =
  SHA-256("walgit-credential-acknowledgement-set-digest-v1" ||
          u32be(len(exact_acknowledgement_set_bytes)) ||
          exact_acknowledgement_set_bytes)
```

#### Credential transition proof

Every credential-control Create or CAS carries one
`CredentialTransitionProof`. First form `transition_projection_bytes` as the
exact deterministic protobuf encoding of the proposed `CredentialControl`
fields 1–9 in tag order. Field 10,
`acknowledgement_proof_digest`, is absent. No proposed `CasToken`, object key,
`ObjectVersionID`, object digest, object size, provider response, or other
metadata assigned by the future Create or CAS is part of the projection. All
normal field bounds, presence rules, ordering rules, and semantic validation
apply before projection. Define:

```text
transition_projection_digest =
  SHA-256("walgit-credential-control-transition-v1" ||
          u32be(len(transition_projection_bytes)) ||
          transition_projection_bytes)
```

The proof is untagged `COSE_Sign1` signed by the same pinned Ed25519 root that
signs verification rings. Its protected header is the exact
deterministic-CBOR map `{1: -8, 4: root_kid}`. Its unprotected header is the
exact empty map. Its external AAD is the exact ASCII bytes
`walgit-credential-transition-proof-v1`. The decoded deterministic-CBOR payload
is at most 7,680 bytes, contains no text strings, and uses these numeric keys:

| Key | Presence and exact value |
|---:|---|
| 1 | required unsigned schema version, exactly `1` |
| 2 | required proof UUIDv7, 16-byte byte string |
| 3 | required unsigned transition kind: `1` bootstrap, `2` install-next, `3` promote-next, `4` retire-previous, `5` revoke-kid, `6` verifier-set-update, or `7` acknowledgement-update |
| 4 | required issued-at, signed 64-bit Unix seconds |
| 5 | required not-before, signed 64-bit Unix seconds |
| 6 | required expiry, signed 64-bit Unix seconds |
| 7 | required domain-separated `verifier_set_digest`, 32-byte byte string |
| 8 | required domain-separated `acknowledgement_set_digest`, 32-byte byte string |
| 9 | required `transition_projection_digest`, 32-byte byte string |
| 10 | required unsigned projection byte length, 1–65,536 |
| 11 | non-bootstrap only: predecessor full physical credential-control key, 1–1,024 ASCII bytes |
| 12 | non-bootstrap only: predecessor `ObjectVersionID`, 1–1,024 bytes |
| 13 | non-bootstrap only: predecessor exact-body SHA-256 digest, 32 bytes |
| 14 | non-bootstrap only: predecessor exact-body size, 1–65,536 |
| 15 | bootstrap only: cutover bootstrap-session UUIDv7, 16-byte byte string |

Keys 1–10 are always present. Bootstrap has key 15 and omits keys 11–14.
Every other kind has keys 11–14 and omits key 15. No other key, variant, or
empty substitute is valid. Key 7 equals proposed field 9. Keys 9 and 10 equal
the digest and length recomputed from the proposed control after removing only
field 10. For a non-bootstrap transition, keys 11–14 equal the exact currently
bound predecessor; for bootstrap, key 15 equals the bootstrap plan session.
The verifier recomputes key 7 from the retained exact root-signed verifier-set
envelope and key 8 from the retained exact acknowledgement-set bytes. It then
verifies every acknowledgement row and requires both retained sets to bind the
same projection, transition kind, and predecessor or bootstrap session as this
proof. The verifier-set issued-at and every acknowledgement time are not later
than proof issued-at; every acknowledgement time is within the proof's
not-before-to-expiry interval. A supplied digest without its exact retained
bytes fails closed.

The root uses strict RFC 8032 verification. Deterministic-CBOR rejection rules
for create intents apply unchanged. The proof requires
`issued_at <= not_before <= expiry`, has a maximum ten-minute lifetime and
30-second skew, and its UUIDv7 timestamp is within 30 seconds of issued-at.
Cloud Core permanently reserves each proof UUID before signing. The exact
proof envelope may retry only the same predecessor and projection. Reusing its
UUID with changed bytes, using a stale predecessor, changing the projection,
or replaying it after another transition fails closed.

After proof verification, set proposed field 10 to
`SHA-256(exact_untagged_CredentialTransitionProof_COSE_Sign1_bytes)` and encode
the final deterministic `CredentialControl`. The proof never includes that
field or metadata assigned to the resulting object, so neither the signature
nor either digest is self-referential. The final control may differ from the
validated projection only by field 10. Its conditional Create or CAS is still
the sole credential commit point.

Cloud Core's credential authority permanently retains the exact untagged
verifier-set envelope, acknowledgement-set bytes, and untagged transition-proof
envelope by their digests for recovery and audit. WalGit receives all three
exact byte strings during Create or CAS, recomputes proof keys 7 and 8, verifies
their signatures and bindings, and persists only the verifier-set and proof
digests in `credential_control`. Retained evidence bytes are not bucket objects,
mutable authorities, or alternate commit points.

Each transition kind permits only its named state change plus
`control_revision + 1` and the new field-10 proof digest. Install-next adds the
one checked descendant and changes no issuer epoch. Promote-next performs the
slot move above and increments `issuer_epoch` by one. Retire-previous removes
the slot and timestamp, appends its data `kid` values to the deny set, and
increments `issuer_epoch` by one if that set grows. Revoke-kid appends exactly
one previously absent bound `kid` and increments `issuer_epoch` by one.
Verifier-set-update changes only field 9. Acknowledgement-update changes no
field in the projection except `control_revision`. Bootstrap uses only the
frozen values above. Combining kinds or changing another field fails closed.

Rotation first writes immutable `next`, CASes it into `credential_control`, and
preloads it on every issuer and verifier. During preload, verifiers accept
`current` and `next`, but the issuer signs only with `current`. A signed proof
that every serving instance, writer, issuer, and other verifier loaded the
exact control version is required before promotion. Each issuer then fences
old-current issuance, reports its last issued-at value, and cannot issue again
until it observes the promoted exact control version. The signed
acknowledgement proof covers that complete issuer fence and verifier set. Its
digest is written by the one atomic credential-control CAS that promotes
`next` to `current` and moves the old `current` to `previous`.
`previous_last_issue_unix_seconds` is the maximum attested issued-at value
across all fenced issuers; when no issuer used the ring, it is the ring's
issued-at value. The issuer then signs only with the new `current`; verifiers
accept only the explicitly bound `current`, optional `next`, and optional
`previous`. An issuer cannot emit a late old-ring envelope after the proof.

There is at most one `previous`. Another promotion cannot occur while that slot
is occupied. Its removal CAS is allowed only after the recorded last issue plus
the maximum 15-minute capability lifetime plus 30 seconds of skew, and after a
signed verifier proof confirms that no accepted unexpired envelope needs it.
Unknown, unbound, stale, invalidly signed, broken-chain, wrong-audience,
wrong-issuer, invalid-time, duplicate, or unsorted ring data fails closed.

A revocation CAS adds the `kid` to the global deny set, which overrides all
three ring slots. Cloud Core must distribute the exact new credential-control
version and collect acknowledgements from every verifier within 30 seconds.
Every verifier renews readiness against the current version; a verifier that
does not acknowledge within 30 seconds leaves readiness and cannot serve or
mutate. The root-signed kind-7 proof and its acknowledgement-update CAS bind
those post-revocation acknowledgements. Only after that CAS can Cloud Core
report revocation complete.
Root-key rotation requires its own signed cutover or deployment ceremony. Ring
rotation changes credential authority, not repository state or terminal
`cutover_control`.

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

Production eligibility requires the exact selected S3-compatible provider to
enumerate current objects, noncurrent versions, delete markers, and all active
multipart uploads with complete pagination. GCS remains supported for
development and non-production contracts. Its non-production exact-delete
contract requires bucket Object Versioning enabled and soft-delete retention
zero. GCS is not eligible for the hard-cut production target because it cannot
enumerate every resumable upload session and delete marker required by the
four-set proof.

### Production bucket administrative safety

Production requires provable exclusive administrative control over bucket
versioning, lifecycle, encryption and KMS retention, and all IAM and provider
policies that can affect the deployment prefix for the full runtime horizon.
Runtime serving, writer, recovery, and reclamation identities have explicit
denies for every administrative change. A provider that cannot expose and
enforce this separation is not production-eligible.

`bucket_admin_control` is the global safety authority. It records an epoch,
state, exact safety-configuration digest, proof digest, and the allowed
administrative principal and policy digests. The safety digest is
`SHA-256("walgit-bucket-safety-v1" || deterministic_cbor(config))`. The CBOR map
uses integer keys 1–21 for schema version, provider account, endpoint, region,
bucket, prefix, versioning state, lifecycle-rules digest,
abandoned-multipart-days, encryption mode, KMS key ID, KMS key version, KMS
retention seconds, object-version retention seconds, object-lock state, bucket
policy digest, IAM policy digest, organization-policy digest, administrative
principal-set digest, runtime-deny-policy digest, and provider-control-policy
digest. IDs are bounded byte strings, times are unsigned 64-bit integers, enums
are unsigned integers, and digests are exactly 32 bytes. Each nested rule or
principal set is deterministic CBOR sorted by its encoded bytes; its field is
the SHA-256 digest of those exact bytes. The digest preimage uses the complete
RFC 8949 deterministic encoding of this map. Duplicate keys, indefinite-length
items, floats, non-shortest encodings, non-canonical map order, unknown keys,
missing keys, and trailing bytes fail closed.

An infrastructure change first CASes `bucket_admin_control` from `STABLE(e)` to
`PREPARING(e+1)`. That CAS blocks new mutation and reclamation admission. The
controller then installs a provider runtime-write deny, revokes every epoch
`e` runtime credential, proves provider-policy convergence, collects
acknowledgements from every serving, writer, recovery, and reclamation process,
and drains every request admitted under epoch `e`. Only then may the dedicated
administration identity change external configuration. An old credential is
never re-enabled.

The controller reads back the complete configuration and roots its exact new
proof and digest. Before publication resumes, it issues, distributes, and
proves loading of new epoch `e+1` runtime credentials. Its final CAS to
`STABLE(e+1)` binds those proofs. A failed or ambiguous change remains fenced
until recovery either proves the new configuration or restores and proves the
prior configuration. A stale actor paused after safety validation is denied by
the provider and cannot publish when it resumes. Terminal `cutover_control`
does not change.

Immediately before every `repo_control` publication and every reclamation
delete, the actor reads the current exact `bucket_admin_control`, requires
`STABLE`, proves that its loaded runtime credential has that exact epoch, reads
the provider configuration, recomputes the safety digest, and requires an exact
match. Each published control version binds the bucket-admin epoch and safety
digest. Readiness performs the same validation and fails on drift, an
unavailable proof, a stale credential epoch, or a non-`STABLE` state. No cached
or advisory value can satisfy this check.

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
Runtime cursors are rooted in control. A production bootstrap holds its
`PREPARING` administrative fence until all four S3-compatible-provider
enumerations return a terminal page.

### Mutation receipt and settlement

Every non-settlement repository mutation creates an unresolved receipt core
before the publishing CAS. This includes mutations whose capacity and event
obligations are both `NONE`, and Create with an explicit prior-control `NONE`.
`INTERNAL_SETTLEMENT` is the only receiptless CAS and is forbidden in receipt
rows. The core binds the mutation ID, mutation kind, a domain-separated digest
of the exact request,
prior `CasToken`, prior control `ObjectVersionID` or explicit `NONE` for
Create, the prior authorizing writer-fence epoch, WAL sequence, and every
immutable dependency digest. For `WRITER_TAKEOVER`, the receipt therefore
binds epoch E while the result binds the landed control at epoch E+1. It
has two closed tagged unions:

- capacity obligation is `NONE` or `CAPACITY`, where `CAPACITY` binds the exact
  capacity-control epoch, shard key, shard `ObjectVersionID`, reservation ID,
  tenant slice, mutation ID, and byte count; and
- event obligation is `NONE` or `EVENT`, where `EVENT` binds the exact event
  UUID, WAL sequence, subscriber-set digest, deterministic result key, and every
  precomputed subscriber-body digest and size.

No absent obligation is represented by an empty or guessed identifier. The
candidate control roots the immutable receipt catalog.

The exact request digest is:

`SHA-256("walgit-repository-mutation-request-v1" || kind_u32_be || request_length_u64_be || exact_request)`.

The domain has exactly the shown ASCII bytes and no terminator. `kind_u32_be`
is the frozen nonnegative `MutationKind` value in four-byte big-endian form.
`request_length_u64_be` is the exact request byte length in eight-byte
big-endian form. The implemented request forms are closed:

- `SETTINGS`: `exact_request` is the raw inline settings byte string.
- `GRANTS`: `exact_request` is `count_u32_be`, followed in caller order by
  `issuer_length_u32_be || issuer || subject_length_u32_be || subject ||
  role_i32_be` for every grant. Caller order is digest-bound. Duplicate
  `(issuer, subject)` entries are rejected; they are not sorted or collapsed.
- `WRITER_TAKEOVER`: the frozen future request form is the raw new-holder byte
  string. The dormant public capability API cannot execute this mutation. A
  future implementation must supply a sealed lease/writer coordination
  authority rather than an administrator capability.

The successful control CAS decides repository state. A timeout or lost response
does not make a landed CAS fail. After the CAS, an immutable result envelope at
a deterministic mutation-ID key records the successful target
`repo_control` key, `ObjectVersionID`, digest, and size. These fields identify
the landed control version, not the result envelope itself. The envelope is
proof only. It cannot publish, authorize, charge capacity, emit an event, or
change repository state.

No unrelated, takeover, or maintenance CAS may follow an unresolved receipt.
After the successful mutation result envelope is materialized, a serialized
internal-settlement control CAS roots that exact result and changes the receipt
catalog row from `UNRESOLVED` to `SETTLED`. It records the exact settlement
mutation ID in the row. The full row remains rooted
indefinitely; settlement does not remove it. Settlement waits for a terminal capacity state
only when the tag is `CAPACITY`. It waits for the event result, exact archives,
and control-rooted archive watermark only when the tag is `EVENT`. A `NONE`
obligation adds no wait. The settlement CAS has no external obligation, creates
no recursive unresolved receipt, and records its own mutation ID in control.
If its outcome is ambiguous, the writer must resolve it with a fresh exact read
before another CAS.

An event core does not contain its future result `ObjectVersionID`. A resolved
envelope supplies that value after publication. Checkpoint, compaction, and
receipt-catalog compaction cannot remove a settled row. A flat bounded receipt
catalog applies backpressure at 4,096 rows or the 512 KiB (524,288-byte)
encoded bound,
whichever comes first. Admission reserves space for the unresolved row's
maximum valid settled result before the publishing CAS. A later evolution can
replace this lower limit only with a separately specified canonical compaction rule.

The persisted `MutationKind` numeric values are frozen:

| Value | Kind |
| ---: | --- |
| 0 | `UNSPECIFIED` |
| 1 | `CREATE` |
| 2 | `PUSH` |
| 3 | `REF_UPDATE` |
| 4 | `LFS_FINALIZE` |
| 5 | `POLICY` |
| 6 | `SETTINGS` |
| 7 | `GRANTS` |
| 8 | `LIFECYCLE` |
| 9 | `CHECKPOINT` |
| 10 | `COMPACTION` |
| 11 | `BUNDLE` |
| 12 | `FOLLOW` |
| 13 | `IMPORT` |
| 14 | `REPAIR` |
| 15 | `PIN` |
| 16 | `EVENT` |
| 17 | `RECLAMATION` |
| 18 | `WRITER_TAKEOVER` |
| 19 | `INTERNAL_SETTLEMENT` |

### Finite quota, capacity, and reclamation

Repository quota is finite and positive. Logical usage charges each unique
canonical Git object's encoded bytes and each unique LFS object's bytes once.
Duplicate content does not charge twice. Derived packs, bundles, checkpoints,
temporary uploads, and recovery copies use separate system capacity. Global
allocatable capacity excludes computed system and emergency reserves.

Capacity uses the fixed repository-hashed shards and the CAS-owned
`capacity_control` allocation authority. Every `STABLE(e)` control version
contains one global allocatable byte budget, one exact tenant-allocation catalog
root, and exactly 256 binary-sorted shard budgets with exact epoch-start shard
key, `ObjectVersionID`, digest, and size proofs. The checked shard-budget sum is
no more than global allocatable capacity. A capacity shard binds the allocation
epoch and its immutable budget. It cannot change that budget within the epoch.
The first byte of `SHA-256(repository_uuid)` selects the shard.

Each shard has a separate binary-sorted current tenant-account table. Every
tenant with retained non-`ABORTED` usage has exactly one account, no account is
extraneous, and its positive current slice is no greater than the immutable
shard budget. Checked `RESERVED + COMMITTING + CHARGED` usage must fit both the
current account and shard budget. Historical reservation rows retain their
original allocation epoch and tenant slice without rewriting. Therefore rows
from older epochs remain exact receipt proofs after redistribution, and mixed
historical slices are valid when their aggregate fits the current account.
`ABORTED` does not charge and an `ABORTED`-only tenant has no account.
The future controller uses two distinct exact shard-object gates. The retained-
budget gate loads the body rooted by the matching
`CapacityShardBudget.shard_object` and binds its shard, prior allocation epoch,
and budget. It works for `STABLE` and for the retained prior plan in both
`PREPARING/DRAINING` and `PREPARING/APPLYING`. The mutable-current gate instead
binds the loaded body to caller-observed provider key, `ObjectVersionID`,
digest, and size, then compares shard, retained current epoch, and budget. It
does not compare that mutable metadata with the historical STABLE epoch-start
proof. After exact page and current-shard loads, the current-shard-view
validator composes the mutable gate, requires every account to equal that
tenant's exact page slice for the selected shard, and requires every current-
epoch non-`ABORTED` reservation to repeat the same slice. Historical terminal
rows keep their earlier proof slice. The admission-specific wrapper
additionally requires `STABLE`. The composed STABLE successor gate binds that
entire predecessor view, a legal transition at caller-observed `now`, and the
candidate shard against the same page, epoch, and budget. The composed
`PREPARING/DRAINING` gate permits only `RESERVED -> ABORTED(expired)`,
`COMMITTING -> CHARGED`, or `COMMITTING -> ABORTED(conflict)`. It rejects new
rows and `RESERVED -> COMMITTING`. Lower-level object, account, and successor
validators are insufficient for publication on their own.

Redistribution uses the closed control states and phases
`STABLE(e) -> PREPARING/DRAINING(e+1) -> PREPARING/APPLYING(e+1) ->
STABLE(e+1)`. The first control CAS retains the complete prior stable plan,
binds the proposed catalog, global budget, and 256 shard budgets, and installs
the exact global writer plus UUIDv7 admission fence. Only terminal reservation
transitions are allowed while draining. The future controller must exact-load
the current and proposed pages and run the cross-object validator so the sum of
all tenant slices in each shard column fits that plan's shard budget.
References alone cannot prove page contents.

After it proves that all 256 exact current shards contain zero `RESERVED` or
`COMMITTING` rows, the second control CAS enters `APPLYING` and binds exactly
256 drained baseline proofs. A drained baseline retains the prior allocation
epoch, budget, shard identity, and key, but its provider version, digest, and
size can be newer than the historical `STABLE(e)` epoch-start proof because
terminal transitions mutated the shard. The exact-baseline validator binds the
loaded body to that proof, rechecks prior epoch and budget, and rejects any
remaining nonterminal row. Each successor is deterministic from
that exact drained body and the target plan: it preserves every terminal
reservation byte-for-byte and replaces current tenant accounts with the exact
target-page slices after proving they cover retained usage. Recovery accepts a
shard only at its exact baseline or at that deterministic successor. A successful advance
finishes with `STABLE(e+1)` binding all 256 exact new epoch-start successor
proofs. A successful reversion first restores and exactly verifies every
changed shard, then publishes `STABLE(e)` with the exact restored proofs; it
does not reuse historical epoch-start `ObjectVersionID` values. A crash or
ambiguous CAS stays fenced and never admits across mixed epochs.

Shards are idempotent, bounded, and reconciled. They are not repository
authority and cannot publish roots or authorize work. There is at most one
`RESERVED` or `COMMITTING` row per repository. Commit-bearing rows also reject
reuse of one mutation ID within the same repository, while another repository
can use the same UUID in its independent namespace.

A reservation moves through these states:

1. `RESERVED` is provisional. It records explicit creation and expiry seconds,
   with `created < expires` and a checked maximum lifetime of 900 seconds. The
   shard successor validator receives caller-observed `now` and accepts a new
   row only when `created <= now < expires`; it rejects future-dated creation.
   No validator reads a clock.
2. `COMMITTING` is non-expiring and binds writer epoch, mutation ID, kind, and
   a closed predecessor. `CREATE` requires explicit `NONE`; every other
   non-settlement kind requires the prior control `CasToken` and
   `ObjectVersionID`.
3. The writer publishes immutable payloads and then CASes `repo_control`.
4. `CHARGED` records the successful control publication exactly once.
5. `ABORTED` releases capacity through one explicit proof arm. Expiry repeats
   the original creation/expiry window and records an observed `now >= expiry`.
   Conflict repeats the exact commit binding and records the durable conflicting
   landed control and mutation that makes the expected CAS impossible.

The public shard successor validator accepts a byte-exact retry without a new
revision. Every real successor advances `control_revision` by exactly one and
changes exactly one reservation through `RESERVED -> COMMITTING`,
`RESERVED -> ABORTED(expired)`, `COMMITTING -> CHARGED`, or
`COMMITTING -> ABORTED(conflict)`. It preserves the shard, allocation epoch,
budget, immutable reservation fields, all untouched rows, and all unaffected
accounts. `RESERVED -> COMMITTING` requires
`created_at <= observed_now < expires_at`. Expiry repeats the exact reserved
window and binds the supplied observed `now`. Terminal rows and same-state rows
cannot change.

CHARGED and conflicting-commit ABORTED require public composition gates. Both
exact-bind the prior COMMITTING shard body to caller-observed provider metadata,
locate the exact reservation row, and bind every prepared receipt
`CapacityObligation` field to that row and shard object. CHARGED additionally
strict-loads the landed `RepoControl` and its exact flat receipt catalog. The
catalog gate validates its content-addressed key, canonical body digest and
size, flat-root counts, identity, one-unresolved maximum, and the exact
representation of `last_internal_mutation_id`. The CHARGED mutation must be
the rooted receipt row. Writer takeover binds landed epoch `E+1`; other
CHARGED mutations bind `E`.

A conflict gate accepts the prepared expected receipt separately because the
failed candidate control never rooted it. It proves that expected mutation is
absent as both a receipt and settlement ID in the exact current catalog, while
the conflicting current ID is represented by that catalog. The durable
`CapacityConflictClass` is closed and corroborated by the exact current
control. `CREATE_CONTROL_EXISTS` requires Create with explicit `NONE` and
accepts any control at the same derived by-path key, including an exact
same-identity occupancy or a different-identity routing-key collision.
`SAME_WRITER_VERSION_ADVANCED` requires non-Create with an exact prior,
different landed `ObjectVersionID`, the same identity, and loaded writer epoch
`E`. `WRITER_EPOCH_ADVANCED` requires the same facts at checked epoch `E+1`.
Every arm binds canonical control key/body/digest/size and its current last
mutation. The conflict proof must originate from a typed current provider GET
at the abort decision. Its stored object version supports later exact replay,
but protobuf validation alone cannot prove provider currentness.

A lost result after the control CAS is success. Reconciliation uses the
control receipt and exact object version to finish `CHARGED`. It resumes a
still-possible `COMMITTING` reservation and never aborts that non-expiring state
because of a clock or timeout. `RepoControl.CapacityBinding` is the
repository's last exact capacity witness, not a claim about the current shared
shard. Admission independently loads the current hashed shard and compares its
epoch, key, budget, and tenant slice. Receipt `CapacityObligation` binds the
exact `COMMITTING` shard `ObjectVersionID`; settlement advances the repository
binding to the exact `CHARGED` shard version.

This slice freezes only the dormant protobuf messages, strict canonical codecs,
semantic validation, keys, and tests. It has no capacity controller, store CAS
adapter, provider operation, server/CLI/config route, V1 adapter, or runtime
reader/writer. The boundary is greenfield: no production V2 capacity objects
exist, no migration or mixed-version behavior is supported, and activation
requires a later hard cut with all readers and writers on the same contract.
Recovery for this dormant slice is code revert only.

Reclamation is typed, bounded by objects and bytes per pass, and resumable from
a control-rooted cursor. A pass exact-version-deletes at most 1,000 objects and
at most 5 TiB. It stops before either next item would exceed a limit and roots
the next cursor. Candidate classes are closed enums, never caller prefixes. The
protection closure contains catalogs and payloads currently rooted by control,
their transitively rooted children, and exact versions retained by unresolved
receipt, event, capacity, pin, recovery, reclamation, or retention obligations.
An unrooted historical catalog is not protected merely because it once existed.
It becomes reclaimable only after the typed traversal proves that no current or
retained obligation reaches it. Every delete names an expected
`ObjectVersionID`. Capacity refunds only after a verified delete. Identity and
control are never reclaimed.

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
`ObjectVersionID`, plus the exact repository-grant issuer and subject. Every
capability-authorized operation matches that grant pair and its required role
in current control. Mutations reauthorize against the exact control version
they CAS and repeat the check after contention. New reads check current control
visibility, lifecycle, exact grant, and authorization epoch. In-flight reads
have a bounded timeout after revocation or deletion.

WalGit does not issue presigned URLs that outlive repository authorization.
LFS upload can stream to an immutable candidate, but finalize reauthorizes and
publishes ownership through the control CAS. Service-build credentials are
separate from user and webhook credentials and enforce full scope and
cancellation checks.

## Future events, fanout, and build pins

The publishing control CAS includes a stable event core with repository UUID,
generation, WAL sequence, mutation ID, and the complete all-ref change set.
One atomic ref transaction has at most 256 changes, all inline. A larger
transaction fails as `REF_TRANSACTION_TOO_LARGE` before any durable write; no
chunked event publication exists. The later immutable result
envelope adds the successful control `ObjectVersionID`. `PushEvent` is versioned
and preserves current repository, ref, branch, before, after, commit, pusher,
forced, created, deleted, and compare semantics. Only branch events start
builds. Tags and other ref events remain observable but do not enqueue a build.

Before any candidate payload, receipt, reservation, or control write, the
writer freezes the set of at most 64 active subscribers and computes the exact
webhook body for every subscriber. `exact_body_bytes` is the RFC 8785 JSON
Canonicalization Scheme encoding of that subscriber's versioned `PushEvent`;
ref changes are ordered by binary ref-name bytes and duplicate ref names are
invalid. Every body must be at most 1,048,576 bytes. Any oversized or
non-deterministic body rejects the whole ref transaction as
`EVENT_BODY_TOO_LARGE` or `EVENT_ENCODING_INVALID`. No partial ref transaction
or event is durable.

An ordered cursor controls delivery only. It never decides repository
correctness. The only delivery transport is an HTTPS `POST` to the registered
callback. HTTP, redirects, queues, polling, and alternate methods are not
delivery substitutes. A callback URL cannot contain user information, a query,
or a fragment. TLS and callback-host validation fail closed.

Each delivery has the stable 16-byte event UUID and a new unique 16-byte UUIDv7
delivery ID. Each retry uses a fresh delivery ID, timestamp, and HMAC while the
event ID stays stable. Let `LP(x) = u32be(len(x)) || x`. The exact HMAC input is:

```text
LP("walgit-webhook-v1") ||
LP("POST") ||
LP(normalized_path) ||
SHA-256(exact_body_bytes) ||
event_uuid_raw16 ||
delivery_uuid_raw16 ||
i64be(unix_timestamp_seconds) ||
hmac_kid_raw16
```

`normalized_path` is the callback URL path only. An empty path becomes `/`.
Normalization removes RFC 3986 dot segments, uppercases percent-escape hex,
decodes percent-encoded unreserved bytes, and preserves escaped reserved bytes,
including `/`. Query and fragment are excluded. The signature is the 32-byte
`HMAC-SHA256` result, encoded as base64url without padding. The headers are
`X-WalGit-Event-ID` and `X-WalGit-Delivery-ID` as lowercase canonical UUID
strings, `X-WalGit-Timestamp` as decimal Unix seconds, `X-WalGit-Key-ID` as 32
lowercase hex digits, and `X-WalGit-Signature` as that base64url value. The body
digest covers the exact transmitted bytes.

The receiver accepts a timestamp only within five minutes of its current time
and keeps a delivery-ID replay entry for at least 15 minutes after first
acceptance. A duplicate delivery ID is rejected before business processing.
Webhook HMAC keys are separate from COSE keys and encrypted through the existing
AEAD references. Each webhook binds exactly one `current` HMAC key and at most
one `previous` key. Senders use only `current`; receivers accept only the bound
pair. Rotation preloads the new key, atomically makes it `current`, and retains
the old key as `previous` for at most 15 minutes after its last issue. A second
rotation waits until `previous` is removed.

Cloud Core handles one delivery in one database transaction. That transaction
records an idempotent inbox row and deterministic per-ref and per-subscriber
outbox rows. Cloud Core returns 2xx and advances its cursor only after commit.
Deployment application is idempotent. Retries, crashes during fanout, and
out-of-order release cannot lose or duplicate deployment effects.

For every build-eligible branch event, at event publication the writer records
an exact configured
`event_to_build_intent_delay`, `max_queue_delay`, `retry_horizon`, and
`max_build_completion_horizon`. The first value is at most 30 days. Each of the
last three values is at most 30 days, and their sum is at most 90 days. The
writer defines `ready_deadline = event_publication_time +
event_to_build_intent_delay`. The publishing event CAS roots a conservative
primary-repository `event_build_retention_floor = ready_deadline +
max_queue_delay + retry_horizon + max_build_completion_horizon`. The floor is
therefore at most 120 days after publication and cannot be shortened. It
retains the exact primary event after-SHA and its Git and LFS closure through
that time. It is computed from configuration known at publication; it never
contains or depends on a future build-intent ID, pin ID, pin expiry, or named-
context decision.
Tags, deleted branches, and other non-build events record a terminal `NO_BUILD`
outcome and do not carry this build-retention floor.

Each immutable subscriber archive body records repository identity, event ID,
delivery outcome, committed time, subscriber identity, body digest, and
retention deadline. It does not record its own store identity. Its retention
deadline is the latest of committed time plus 30 days, the subscriber
obligation, the full delivery retry horizon, and, when present, the
control-rooted `event_build_retention_floor`. A verified archive watermark has at most 64
archive-root references and records the subscriber set, highest complete WAL
sequence, each archive's exact key, `ObjectVersionID`, digest, and size,
committed time, and retention deadline. Each reference is at most 4,096 encoded
bytes, and the complete watermark is at most 524,288 encoded bytes. One
`repo_control` CAS must root that exact watermark before a checkpoint can
compact future event state, settlement can mark its receipt `SETTLED`, or
reclamation can delete any event dependency. The receipt row remains rooted
indefinitely in this flat-catalog slice. Archive, watermark, settlement, and reclamation
retention use the conservative event floor. They do not wait for an unknown
future pin. Missing, ambiguous, expired-but-unverified, or partially archived
state applies backpressure and remains live.

For a build-eligible branch event, Cloud Core first creates a durable
`PREPARING` build-intent row in its database. The row binds an idempotency key,
the exact event and primary event SHA, every named-context selector and
configuration revision, `ready_deadline`, all four configured horizons, and the
event retention floor. No build outbox row exists in `PREPARING`.

By `ready_deadline`, every exact primary and named-context pin must exist and be
recorded. One Cloud Core database transaction then conditionally changes the
intent from `PREPARING` to `READY` and creates its deterministic exact build
outbox row. If any pin or record is missing at the deadline, one database
transaction instead records terminal `NO_BUILD_DEADLINE_EXPIRED` on the event
and intent and creates deterministic compensation-outbox rows for every partial
pin. Terminal state permanently rejects a later `READY` transition, pin
attachment, outbox creation, or enqueue.

Every event-specific pin request binds the build-intent ID and
`ready_deadline`. WalGit rejects a request admitted at or after that deadline,
and Cloud Core never accepts a pin result after it. If a pre-deadline pin CAS is
paused or its result is ambiguous until after terminal state, exact-read
resolution can classify it only as a compensatable orphan. It cannot satisfy
the intent or authorize `READY` or enqueue. Reconciliation performs each
compensation through that repository's fenced `repo_control` CAS. It cannot
remove a closure retained by another obligation.

A selector is either `EXACT_SHA` or `CURRENT_REF`. The primary event selector
is `EXACT_SHA` and equals the event's exact after-SHA. A named `CURRENT_REF`
selector remains unresolved until its build pin CAS. That CAS resolves the ref
head from the exact `repo_control` version it updates and stores the resolved
SHA in the pin and intent. No selector is resolved earlier, re-resolved after
the CAS, or replaced by a branch fallback.

Each configured named `EXACT_SHA` context has a standing, fenced configuration-
time pin before that configuration becomes eligible for events. The standing
pin roots the unchanged exact SHA and its Git and LFS closure. Before each event
can use that configuration revision, Cloud Core proves that the pin expires no
earlier than that event's `ready_deadline + max_queue_delay + retry_horizon +
max_build_completion_horizon`; it renews the pin through an exact fenced CAS
first or keeps the configuration ineligible. The build intent records that
exact standing pin as its named-context pin by `ready_deadline`.

Configuration removal atomically makes the revision ineligible for new events
and records its last eligible event and required pin horizon. Reconciliation
keeps or renews the standing pin through that event's `ready_deadline` plus the
remaining queue, retry, and completion horizon, then releases it through a
fenced compensation CAS. Ambiguous renewal or release requires an exact read.
Removal cannot release a closure retained by a build, event, recovery, or other
configuration.

Every repository's pin independently roots its exact Git and LFS closure. The
planned enqueue time is no later than `ready_deadline + max_queue_delay`. Each
pin expiry is no earlier than the planned enqueue time plus `retry_horizon +
max_build_completion_horizon`. Queue, retry, and completion horizons still sum
to at most 90 days. A short pin must be renewed before `READY`; after the
deadline, the intent becomes terminal instead of renewing or enqueueing late.

The queue carries the recorded exact SHAs, pin IDs, control versions, expiries,
and credential references for every context. The runner verifies all of them
before use. Reconciliation resumes a non-expired `PREPARING` intent, performs
terminal compensation, or repairs the one READY/outbox transaction. It never
enqueues a partially pinned, expired, terminal, or late build.

## Future recovery contract and fault model

`P || "v2/recovery/recovery_control.pb"` is the sole global recovery authority.
Its CAS state machine is:

```text
IDLE(g0)
  -> PREPARING(g1, recovery_id)
  -> FENCED(g1)
  -> RESTORING(g1)
  -> VERIFYING(g1)
  -> RELEASING_COMMIT(g1)
  -> IDLE(g2, last_result = COMMITTED)

PREPARING | FENCED | RESTORING | VERIFYING
  -> REVERTING(g1)
  -> RELEASING_ABORT(g1)
  -> IDLE(g2, last_result = ABORTED)
```

The first CAS binds the recovery UUID, tenant, project, repository UUID and
generation, canonical path bytes, both path digests, source control key and
exact version or explicit `NONE`, target namespace, signed intent digest, and
recovery epoch. From `PREPARING` until the final `IDLE` CAS, every repository
create, mutation, and reclamation admission for that identity or path reads this
authority and rejects work outside the recovery controller. Ordinary reads keep
the one-`repo_control` path; when control exists, the recovery CAS also sets its
lifecycle to `FENCED`.

`PREPARING` revokes target writer and reclaimer credentials, collects every
serving and writer acknowledgement, and drains admitted requests before the CAS
to `FENCED`. Recovery then restores bottom-up into new immutable target objects
and catalogs. A signed mapping records every source key and
`ObjectVersionID` to its target key and `ObjectVersionID`. Target catalogs
contain no old references. Exact parent roots in `recovery_control` and
`repo_control` bind journals, mappings, catalogs, and payload references.
`VERIFYING` proves the complete Git, WAL, LFS, event, pin, catalog, receipt, and
capacity closure plus a zero-old-reference all-version scan. One exact final
`repo_control` CAS publishes the recovered repository root.

`RELEASING_COMMIT` issues and loads a new writer and authorization epoch;
`RELEASING_ABORT` restores and verifies the prior authority without publishing
the candidate. Only the final exact `IDLE` CAS releases the create, mutation,
and reclamation fence. Every state roots bounded idempotent step proofs. A crash
or ambiguous CAS resumes or reverts from a fresh exact read and never releases
on time, lease expiry, or an unrooted side effect.

If `repo_control` is missing, Cloud Core can authorize same-identity recovery
only with the signed recovery intent through this state machine. Recovery never
invents a new UUID, generation, tenant, project, or path.

The zero-acknowledged-loss claim covers corruption and logical overwrite or
delete within one correctly versioned bucket. It excludes loss of the bucket,
account, region, KMS key, or a permanently deleted object version. Those risks
require independent replication or backup and are not hidden by the RPO claim.

An RTO of four hours is valid only after exact selected S3-compatible-provider
throughput and sizing equations pass with two-times headroom. Writer scratch
sizing uses fixed-thin, index, and expanded-object peaks rather than a fixed
guess.

## Future cutover state machine

### Fresh-prefix bootstrap

V2 production uses one fresh deployment prefix `P` on the exact selected
S3-compatible provider. It does not adopt, backfill, translate, or import V1
`manifest.pb` repositories. No production repository data exists in `P` before
bootstrap. Old development data stays in its old prefix and is not changed.

The first durable action is one conditional `Create` of
`P || "v2/control/cutover_control.pb"` in `OPEN(g0)`. It binds the target
provider configuration, bootstrap session UUID, and intended safety policy, but
does not claim that the prefix is empty. An ambiguous Create is resolved only
by an exact read of its key, `ObjectVersionID`, digest, and session. The next
action is the control CAS from `OPEN` to `PREPARING`. No IAM, administration,
route, worker, credential, legacy, or other external change may occur before
that CAS lands.

Only in `PREPARING` may the controller install the exclusive bucket IAM and
administrative fence. That fence makes the cutover administration identity the
only actor able to change provider safety configuration and denies all legacy
and runtime writes, deletes, and multipart starts under `P`. The controller
revokes old runtime credentials, proves provider-policy convergence, collects
acknowledgements from every old writer, and drains admitted requests.

The selected provider must prove one maximum request, signature, and multipart
admission horizon `H`, with `0 <= H <= 300` seconds, plus a monotonic policy and
write-admission audit watermark. After convergence and drain, the controller
waits the full `H` without reopening writes and records the last admitted
mutating-request watermark. Proof reads do not advance it. A provider without a
bounded, testable horizon and stable write-admission watermark is
production-ineligible.

The controller then verifies versioning, lifecycle, encryption, KMS retention,
and the full provider-policy closure. Before any initial control-plane object
Create, a `PREPARING` CAS roots an inline bootstrap creation plan. The plan has
at most 262 rows: 256 capacity shards plus exactly one initial key ring,
`credential_control`, `bucket_admin_control`, `capacity_control`, empty
tenant-capacity catalog page, and `recovery_control`. No other type is valid.

Every plan row is appended by CAS before its matching Create and binds the exact
deterministic key, body digest, size, type, dependency-row indexes, and state
`PLANNED`. One CAS can append a bounded batch. The first dependency stage has
260 independent rows: 256 shards, the key ring, empty tenant catalog,
`bucket_admin_control`, and `recovery_control`. After their assigned versions
are known, the next CAS resolves that stage and appends the exact
`credential_control` and `capacity_control` parent rows. The plan is append-only
within one cutover generation and fits inside the 1 MiB `cutover_control` bound.

For the initial credential-control row, the resolved key-ring version first
fills the frozen bootstrap `current` root. The controller then forms the
field-10-free projection, verifies the root-signed bootstrap transition proof
for this bootstrap session, inserts the exact proof digest as field 10, and only
then appends the final control key, body digest, and size to stage two. Cloud
Core retains the proof bytes; they are not a 263rd plan row or a bucket object.

Each initial object uses conditional Create. One stage runs at most 32 Creates
concurrently. Success returns its assigned `ObjectVersionID`; one batched
cutover CAS changes all completed rows to `RESOLVED` and binds each exact target
key, `ObjectVersionID`, digest, size, and type. Thus the healthy two-stage plan
needs at most three plan CASes: append stage one, resolve stage one while
appending stage two, and resolve stage two. An ambiguous Create is resolved by
exact read: absence retries Create, an exact byte match records the returned
`ObjectVersionID`, and any mismatch fails the hard cut. If the process crashes
after Create but before the resolving CAS, each still-`PLANNED` exact row makes
its matching object retry-resolvable rather than orphaned. No planned object is
operational authority before its row is `RESOLVED` and its own authoritative
parent roots it.

With all 262 rows resolved and writes still denied, the controller enumerates
every current object, noncurrent version, delete marker, and active multipart
upload under `P`. It fetches and verifies every version in the allowlisted
control-plane graph:

- the complete `cutover_control` transition, digest, generation, bootstrap
  session, creation-plan, and row-resolution chain;
- every `bucket_admin_control` and `credential_control` version and each exact
  verification-ring version that those controls root;
- every `capacity_control` version, its exact empty tenant catalog page, and all
  256 capacity shards rooted by the bootstrap chain; and
- every `recovery_control` version rooted by the bootstrap chain.

The graph must close from exact parent references. An object or historical
version is allowed only when its key, `ObjectVersionID`, digest, size, type,
transition predecessor, generation, and bootstrap session match that graph.
During retry, each unresolved `PLANNED` row permits only its one exact matching
object while the controller resolves the batch. Repository-data counts remain
zero. Any other current object, noncurrent version, delete marker, multipart
upload, control transition, or orphaned object fails the hard cut. Retry never
assumes cleanup or deletes an unexpected entry.

The four scanned sets have exact, disjoint classifications. A current object is
an object version that the provider reports as latest for its key and that is
not a delete marker. A noncurrent object is every object version that the
provider does not report as latest. If a delete marker is latest, that key has
no current object and all of its object versions are noncurrent. The delete-
marker set contains every delete marker, whether or not it is latest, and
records its latest bit. The multipart set contains every active multipart
upload. A provider entry that cannot be assigned once under these rules, or is
assigned to more than one set, fails the proof.

The scan uses exact provider-returned key, `ObjectVersionID`, and upload-ID
bytes. Let `LP(x) = u32be(len(x)) || x`; `u8` is one unsigned byte and `u64be`
is one unsigned 64-bit big-endian integer. Set kinds are current object `1`,
noncurrent object `2`, delete marker `3`, and active multipart upload `4`. Let
`E = LP("walgit-cutover-entry-v1")`. Entries have only these encodings:

```text
object(k) = E || u8(k) || LP(key) || LP(ObjectVersionID) ||
            u64be(size) || SHA-256(exact_version_content)
marker    = E || u8(3) || LP(key) || LP(ObjectVersionID) || u8(is_latest)
upload    = E || u8(4) || LP(key) || LP(upload_id)
```

Here `k` is `1` or `2`, and `is_latest` is exactly `0` or `1`. Exact-version
GET supplies the object content digest, and exact-version HEAD, GET, and list
sizes must agree. Delete markers and active uploads have no committed content
size or content digest, so their encodings omit those fields. Within each set,
the controller sorts complete encoded entries in unsigned lexicographic byte
order and rejects an exact duplicate. It can use bounded spill files and an
external merge, but it must finish every paginated enumeration before it
accepts a digest.

For set kind `k`, with sorted entries `e1` through `en`, the streaming set
digest is:

```text
SHA-256(LP("walgit-cutover-set-v1") || u8(k) ||
        LP(e1) || ... || LP(en) || u64be(n))
```

Each scan performs exactly two shared S3 traversals. One complete
`ListObjectVersions` traversal feeds current objects, noncurrent objects, and
delete markers from each entry's provider type and `IsLatest` value. One
complete `ListMultipartUploads` traversal feeds active uploads. Requests use
prefix `P`, no delimiter, and the provider maximum page size of 1,000. No
per-set LIST or cursor exists.
The current-object, noncurrent-object, and delete-marker set clauses share the
exact version-traversal page count and cursor-chain digest. The upload set uses
the multipart-traversal page count and cursor-chain digest. A set cannot carry
independent traversal evidence.

Traversal kind `1` is versions and kind `2` is multipart uploads. Let
`C = LP("walgit-s3-list-cursor-v1")`. A canonical cursor is:

```text
version_cursor = C || u8(1) ||
  u8(key_marker_present) || LP(key_marker_or_empty) ||
  u8(version_id_marker_present) || LP(version_id_marker_or_empty)

multipart_cursor = C || u8(2) ||
  u8(key_marker_present) || LP(key_marker_or_empty) ||
  u8(upload_id_marker_present) || LP(upload_id_marker_or_empty)
```

Each presence value is exactly `0` or `1`. An absent component has presence
`0` and a zero-length LP value. A present component has presence `1` and its
exact provider-returned raw bytes, including an empty value if the provider
returned one. Key, version-ID, and upload-ID marker values are each at most
1,024 bytes, so a canonical cursor is 39–2,087 bytes. The initial request cursor
has both components absent.

This production contract uses general-purpose S3 pagination. When a response
is truncated, both required next components must be present: `NextKeyMarker`
and `NextVersionIdMarker` for versions, or `NextKeyMarker` and
`NextUploadIdMarker` for multipart uploads. Their canonical response-next
cursor becomes the exact next request cursor, with the same presence bits and
raw bytes. A nontruncated terminal response must have both next components
absent. Directory-bucket pagination that omits the upload-ID marker is not
eligible. The scanner rejects a missing required component, a next request
that differs from the preceding response-next cursor, a repeated request
cursor, a truncated response whose next cursor repeats any prior request, or a
nontruncated response with a next component present.

For traversal kind `t`, page `i` binds request cursor `ri`, response-next cursor
`ni`, and the response's exact truncation bit `bi`. With `p >= 1` pages, the
streaming cursor-chain digest is:

```text
SHA-256(LP("walgit-s3-cursor-chain-v1") || u8(t) ||
        for i = 0..p-1:
          u64be(i) || LP(ri) || u8(bi) || LP(ni) ||
        u64be(p))
```

All nonterminal `bi` values are `1`; the last is `0`, and its `ni` is the
canonical both-absent cursor. The scanner hashes this chain incrementally and
retains only its page count and digest. Entry duplicate checks span page
boundaries, including many versions and delete markers for one key.

One scan record has this exact binary encoding, with the four set clauses and
then the two traversal clauses in ascending kind order:

```text
LP("walgit-cutover-scan-v1") ||
u64be(start_unix_milliseconds) || u64be(finish_unix_milliseconds) ||
LP(request_audit_high_watermark) ||
for k = 1..4:
  u8(k) || u64be(item_count) || set_digest_raw32 ||
for t = 1..2:
  u8(t) || u64be(page_count) || cursor_chain_digest_raw32 ||
u64be(repository_data_count) || u64be(allowlisted_graph_count)
```

With the 4,096-byte watermark maximum, a scan record's exact worst case is
4,404 bytes, below its 8,192-byte hard cap. Its digest is
`SHA-256(LP("walgit-cutover-scan-digest-v1") || LP(scan_record))`. Both scans
must have complete pagination, identical per-set counts and set digests,
identical zero repository-data and allowlisted-graph counts, and the same
request-audit high watermark. Their start and finish times, page counts,
cursor-chain digests, and scan-record digests remain distinct evidence.

The shared request-audit high watermark is the provider's exact last admitted
mutating-request or write-admission watermark after policy convergence, writer
drain, and the full `H` wait. Bootstrap LIST, exact-version HEAD, and
exact-version GET proof reads do not advance it. A provider that cannot expose
that stable write-admission watermark separately from proof reads is
production-ineligible.

The final proof uses a dedicated pinned 32-byte Ed25519 bootstrap public key.
Define `bootstrap_kid = first16(SHA-256("walgit-bootstrap-ed25519-kid-v1" ||
bootstrap_public_key))`; it is the first 16 digest bytes in wire order and is
encoded as a 16-byte CBOR byte string. The production candidate and `OPEN` bind
that exact public key and key ID before a scan. The proof is an untagged `COSE_Sign1` with
the exact deterministic-CBOR protected map `{1: -8, 4: bootstrap_kid}`, an
empty unprotected map, an attached payload, and external AAD equal to the exact
ASCII bytes `walgit-cutover-proof-v1`. It uses the same deterministic-CBOR and
strict Ed25519 rejection rules as create intents. No verification-ring key can
substitute for the dedicated bootstrap key.

The proof payload is one deterministic-CBOR integer-keyed map. All configured
identifiers are byte strings containing the exact bound bytes, not normalized
text. It has only these required keys:

| Key | Type and value |
|---:|---|
| 1 | unsigned proof schema, exactly `1` |
| 2 | bootstrap-session UUIDv7, 16-byte byte string |
| 3 | unsigned cutover generation |
| 4 | exact prior cutover key byte string, 1–1,024 bytes |
| 5 | exact prior cutover `ObjectVersionID` byte string, 1–1,024 bytes |
| 6 | exact prior cutover `CasToken` byte string, 1–256 bytes |
| 7 | unsigned intended transition, exactly `1` for `PREPARING -> PREPARING_WITH_FOUR_SET_PROOF` |
| 8 | provider byte string, 1–128 ASCII bytes |
| 9 | provider account byte string, 1–256 bytes |
| 10 | endpoint byte string, 1–2,048 ASCII bytes |
| 11 | region byte string, 1–256 ASCII bytes |
| 12 | bucket byte string, 1–256 ASCII bytes |
| 13 | deployment-prefix byte string, 0–256 ASCII bytes |
| 14 | fixed integer-keyed mode map described below |
| 15 | 32-byte safety-configuration digest |
| 16 | provider IAM or policy-revision byte string, 1–4,096 bytes |
| 17 | request-audit high-watermark byte string, 1–4,096 bytes |
| 18 | unsigned admission horizon `H`, in seconds |
| 19 | 32-byte production-image digest |
| 20 | 32-byte resolved creation-plan digest |
| 21 | exact first scan-record byte string, 1–4,404 bytes |
| 22 | 32-byte first scan-record digest |
| 23 | exact second scan-record byte string, 1–4,404 bytes |
| 24 | 32-byte second scan-record digest |

The key-14 map has exactly six byte-string values: key 1 addressing mode, key 2
credential mode, key 3 versioning mode, key 4 lifecycle mode, key 5 encryption
mode, and key 6 KMS mode. Each value is 1–128 ASCII bytes. At all simultaneous
maxima, the 24-key deterministic-CBOR payload is at most 23,557 bytes. The
untagged four-item COSE array, exact 21-byte protected-map encoding and byte-
string wrapper, empty map, payload wrapper, and 64-byte-signature wrapper make
the complete envelope at most 23,650 bytes. The declared envelope limit remains
65,536 bytes. A contract linter repeats this exact expansion and rejects any
schema change that exceeds either computed maximum or the declared limit.

After the creation-plan resolution CAS, the controller reads and fixes the
exact prior cutover key, `ObjectVersionID`, and `CasToken`. No durable write
occurs until both scans finish. It then builds and signs the deterministic
payload locally, embeds the exact proof in the next `cutover_control`
candidate, and uses the bound prior token for the proof-rooting CAS while state
remains `PREPARING`. The payload does not include the candidate control's
future `ObjectVersionID`, digest, or size, or the proof envelope's digest, so it
has no self-digest cycle. The store result supplies the new control version.
Any session, generation, prior key, prior version, prior token, transition,
provider configuration, key ID, or scan mismatch rejects replay. An ambiguous
CAS is resolved by an exact control read before another attempt. No standalone
proof object exists. A crash repeats graph verification and both scans before
`PREPARED`.

All later V1 disablement, legacy route barriers, drains, worker and retry stops,
credential revocations, runtime-IAM installation, and authority transfers are
rooted idempotent `PREPARING` steps. Repository creation stays fenced until
`ACTIVE`. Every later repository starts as a new immutable UUID with generation
1 from a valid signed create intent at the routing-digest-derived control key.
No read, write, recovery, or discovery path can adopt V1 state. There is no
legacy identity migration or path-reuse exception.

A crash before `PREPARING` leaves only the `OPEN` control write and resolves
only the control CAS. A crash after `PREPARING` is owned by the state-machine
recovery: it resumes from rooted step proofs or restores and verifies every
changed IAM, administrative, legacy, route, worker, and credential state before
`ABORTED`.

### Cutover transitions

One signed `cutover_control` record is the global cutover authority. Its state
machine is:

```text
OPEN(g0) -> PREPARING(g1) -> PREPARED(g1) -> ACTIVE(g1)
                         \-> ABORTED(g1) -> PREPARING(g2)
```

`ACTIVE` is terminal. Each generation validates linearly at repository commit
and build enqueue. After the conditional `OPEN` Create, the CAS to `PREPARING`
happens before any external cutover effect other than those two required control
writes. Every ingress fence, Forgejo barrier, drain, worker stop, retry stop,
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

Critical PR work still targets a 15-minute P95. In addition, every required PR,
provider, evidence, recovery, cutover, and promotion job declares
`timeout-minutes` of at most 15. Each provider job gives test work at most 12
minutes and reserves at least the final 3 minutes for unconditional,
fail-closed cleanup and evidence upload. Provider evidence runs
production-locally as parallel bounded jobs. The admission-horizon job spends
at most 5 of its 12 test minutes waiting for `H` and reserves at least 7 test
minutes for policy convergence and two complete scans. The complete provider
workflow has a 30-minute cap. A 60-minute fallback is not allowed. Linting rejects a
missing or larger required-job timeout, a provider test budget above 12
minutes, a cleanup reserve below 3 minutes, or a workflow cap above 30 minutes.
Timing evidence enforces the same bounds.

The PR2 exact-production-provider primitive gate runs only against the selected
S3-compatible provider and proves:

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
- paginated post-`PREPARING` proof with exactly one shared
  `ListObjectVersions` traversal for current objects, noncurrent versions, and
  delete markers and one `ListMultipartUploads` traversal for active uploads
  per scan, with canonical cursor continuity, zero repository data, and only
  the exact allowlisted control-plane graph;
- `OPEN -> PREPARING` before the exclusive IAM or administrative fence and
  before every other external cutover effect;
- exclusive-IAM denial of a concurrent legacy or runtime writer during the
  post-`PREPARING` four-set proof;
- provider-policy convergence, a bounded admission horizon, request-audit high
  watermarks, and two matching complete scans before the proof CAS, with
  `H <= 300` seconds inside the 12-minute test budget;
- exclusive administrative control, exact safety-configuration digest checks,
  drift failure, and the global writer fence around every infrastructure
  change.

The later production gate proves full-scale object counts, throughput,
retention, event replay and fanout, build pins, restore, cutover, and recovery
on the exact selected S3-compatible provider and exact production candidate
digest.

## Future vertical acceptance

These scenarios are required by later gates. PR1 does not implement them.

- A raw-path conformance corpus proves exact one-time decoding, binary path
  identity, global uniqueness, routing-digest-derived control lookup,
  management-route separation, `canonical_path_digest` verification,
  independent raw and routing digest collision failures, and permanent
  tombstone path denial.
- Namespace tests prove every V2 object uses its closed full physical key.
  Empty and non-empty `P` vectors prove that the V2 adapter strips `P` exactly
  once for a configured prefixed store call, restores it exactly once on every
  metadata, exact-version, and listing result, and rejects prefix mismatch,
  relative-key authority, and `P || P || S`. Immutable bodies bind identity and
  semantic content but never their own key, `ObjectVersionID`, digest, or size.
  Each authoritative parent binds those exact values for its target. Standard
  raw Git pack, LFS, and bundle bytes remain unmodified. No host, capacity,
  lease, event, or recovery object can replace the routing-digest-derived
  control authority.
- Byte-vector tests prove every allowed leaf and reject every unlisted leaf.
  They verify deterministic protobuf bytes, raw payload bytes, complete signed
  envelope bytes, exact verification-ring COSE bytes, and the credential-control
  transition projection as distinct digest preimages.
- Descriptor tests prove that every variable field, message, repeated field,
  and catalog has the stated numeric bound. Boundary tests prove exact
  inline-to-catalog transitions, mutually exclusive representations, bounded
  cold reads, backpressure, and compact-or-reject behavior. The linter expands
  64 maximum 4,096-byte archive-root references with maximum keys and
  `ObjectVersionID` values and proves that the complete watermark stays within
  524,288 bytes.
- Cross-language deterministic-CBOR and COSE vectors cover create and
  capability payloads, independent keys 14 and 17, swapped or conflated digest
  rejection, required grant keys 35 and 36, exact grant-pair and purpose-role
  checks, every rejected encoding, UUIDv7 and time boundaries, same-control-key
  exact replay and changed-byte conflict, exact data and root `kid` headers, all
  slot/state matrix cells, key-ring signatures, current/next preload, atomic
  promotion, bounded previous retirement, the 30-second revocation deadline,
  stale verifiers, and immediate deny-set enforcement. Credential-control wire
  vectors cover tags 1–10, required and optional presence, maximum revoked-key
  cardinality and ordering, proof digests, complete ring-root metadata and body
  binding, legal evolution, and rejection of every other slot transition.
- Ring-lineage vectors cover the exact bootstrap values, checked
  `current + 1` installation, exact prior-ring digest, promotion, and
  retirement. Negative vectors cover rollback, fork publication, skipped and
  wrapped or overflowing epochs, duplicate ring/root/key identities, digest
  collision, deny-set overflow, and retired-key reuse.
- Cross-language credential-transition vectors cover the exact field-10-free
  protobuf projection and domain-separated digest; the exact root-signed
  verifier-set COSE headers, AAD, numeric payload, bounded member rows, sorting,
  and domain-separated digest; and the exact acknowledgement-set map, member
  signature preimages, one-to-one ordering, and domain-separated digest. They
  also cover proof keys 7/8 recomputation from retained bytes, the proof's
  untagged COSE headers, external AAD, numeric payload variants, pinned-root
  signature, predecessor full key/version/digest/size, bootstrap session, final
  field-10 insertion, and exact retry. Negative vectors cover a self-cycle,
  future object metadata, projection or predecessor corruption, missing,
  duplicate, extra, reordered, wrong-role, and bad-signature members,
  unknown/duplicate/missing CBOR keys, digest-only evidence, changed-byte
  proof-ID reuse, stale-proof replay, and wrong-root signatures.
- A valid signed create intent creates the exact UUID, generation, path,
  canonical path digest, routing digest, visibility, quota, and initial admin
  once. Cloud Core vectors prove permanent global intent-ID uniqueness before
  signing; WalGit vectors prove that replay state is scoped to the one derived
  `repo_control` key and creates no global index. Unsigned, altered, expired,
  cross-tenant, cross-project, and same-key replay-conflict requests publish
  nothing.
- Every client and system mutation becomes visible only through one
  `repo_control` CAS. Mutable side state cannot publish, authorize, or replace a
  root.
- A successful CAS with a lost response is followed only by result
  materialization and the receiptless settlement CAS. Settlement preserves the
  row as `SETTLED` and never creates a recursive settlement receipt. Tagged
  `NONE`, `CAPACITY`, and `EVENT` obligations wait for exactly their present
  dependencies and no absent dependency. The maximum-key,
  maximum-`ObjectVersionID`, 64-subscriber case settles only after its exact
  watermark is rooted, and reclamation cannot delete any referenced archive
  before that settlement and retention deadline.
- Grant revocation racing a push has one linear winner. A stale push cannot
  reauthorize or publish after revocation.
- Writer takeover fences every former-writer surface. Lease clock skew and
  expiry alone never grant write authority.
- Exact logical quota boundaries, duplicate Git and LFS objects, all reservation
  crash points, and verified refunds preserve finite capacity. Cross-shard tests
  exhaust many shards simultaneously and prove the immutable shard budgets,
  tenant slices, and global allocation cannot oversubscribe. Redistribution
  rejects any nonterminal reservation and resumes safely across every shard CAS.
- Typed reclamation stays within object and byte budgets, resumes from its
  cursor, preserves every current, transitive, and obligation-retained root, and
  exact-version-deletes only eligible versions. A superseded unrooted historical
  catalog becomes eligible after its last retention obligation expires.
- Bucket lifecycle tests prove that only abandoned multipart uploads expire
  automatically. KMS tests prove that every retained object version remains
  decryptable for its full retention horizon.
- Bucket-administration tests change versioning, lifecycle, KMS, encryption,
  IAM, and provider policy only after the global `PREPARING` fence. They inject
  drift immediately before publication and reclamation and prove fail-closed
  readiness and no capacity refund. A writer paused after safety validation is
  denied after credential revocation and cannot publish when it resumes.
- Event tests cover HTTPS-POST-only delivery, canonical path and HMAC vectors,
  five-minute freshness, unique delivery IDs, 15-minute replay retention,
  current/previous HMAC rotation, 256-change and 1 MiB body boundaries, 64
  active-subscriber boundary and backpressure, deterministic per-subscriber
  bodies, rejection before any durable write, lost CAS responses, post-CAS
  materialization, fanout crashes, out-of-order delivery, retention deadlines,
  and the exact control-rooted archive watermark before every removal path.
  The maximum-key, maximum-`ObjectVersionID`, 64-subscriber watermark passes
  settlement and remains protected from reclamation until its exact deadline.
- Build tests ACK an event, stall each primary or named pin and the READY/outbox
  transaction across `ready_deadline`, and race reclamation against the
  control-rooted 120-day primary event floor. By the deadline, all exact pins
  and the one READY/outbox transaction exist, or one terminal no-build decision
  durably schedules partial-pin compensation. Late pin results, READY, outbox,
  and enqueue remain denied after crashes and ambiguous CAS outcomes.
- Standing-pin tests refuse to activate a named `EXACT_SHA` configuration before
  its exact Git/LFS closure is pinned, renew it through the last eligible event's
  ready deadline and remaining horizon, and remove it without releasing another
  obligation's closure. `CURRENT_REF` tests move and reclaim the ref before and
  after its build pin CAS and prove that only the SHA resolved by that CAS stays
  rooted. Maximum queue, retry, completion, and named-context horizons preserve
  every exact closure consumed by the runner.
- Recovery tests crash at every global recovery-control state and credential
  drain, restore from every journal phase, prove no old references, recover
  missing control only under the signed global fence, and release create,
  mutation, and reclamation only after the terminal exact CAS. They reject
  faults outside the stated one-bucket loss model.
- Cutover tests include open Forgejo sessions, worker and retry activity,
  crashes at every state and external step, verified abort restoration, stale
  generation requests, and terminal `ACTIVE` behavior.
- Bootstrap tests prove conditional `OPEN`, then `PREPARING`, then the exclusive
  IAM and administrative fence, credential revocation, policy convergence, the
  bounded admission wait, and two matching complete S3 scans. They cover every
  state, scan, proof-rooting, and external crash point; exercise the 262-row
  creation-plan bound, 32-Create concurrency bound, three healthy plan CASes,
  and a crash after every Create but before its batched resolving CAS; verify
  the complete allowlisted graph and exact version history; reject an
  unplanned, mismatched, unexpected, or V1 object and concurrent writer without
  cleanup; and prove no post-`ACTIVE` path adopts V1 state. Shared cross-language
  vectors cover all four entry classifications, exact LP/u8/u64 encodings,
  content corruption, lexicographic order, and duplicate rejection. Cursor
  vectors split pages between many versions and delete markers for the same key
  and cover present-empty versus absent components, missing required next
  markers, response-next/request mismatch, repetition, terminal markers, and
  the two shared traversal page-count and chain digests. They cover every set
  and scan digest, the exact 4,404-byte scan and 23,650-byte proof maxima,
  deterministic proof payload bytes, the dedicated bootstrap `kid` and COSE
  signature, and replay rejection across session, generation, prior control
  version, prior `CasToken`, or transition. A vector also proves that the proof
  excludes its candidate control and envelope digests and therefore has no
  self-digest cycle.
- GCS tests remain development and non-production only. They prove Object
  Versioning and zero soft-delete retention where exact deletion is tested and
  prove that production eligibility fails because the four-set resumable-upload
  and delete-marker proof is unavailable.
- Secret and revocation tests cover Git, LFS, API, settings, policy, webhook,
  build, and capability surfaces.
- Exact-provider tests bind the selected endpoint and candidate digest and
  exercise every PR2 primitive plus the later scale and recovery gates.
- Promotion tests prove that production consumes the exact candidate digest
  that passed all evidence, with no rebuild or mutable-tag substitution. CI
  lint tests reject every required job above 15 minutes, every provider test
  budget above 12 minutes, every cleanup reserve below 3 minutes, and every
  provider workflow above 30 minutes. The horizon job also proves that at most
  5 test minutes cover `H` and at least 7 test minutes remain for convergence
  and two scans.
