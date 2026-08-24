# Production architecture charter

Status: frozen V5.3 production target. PR1 implements only the storage and
preservation gate described below. The V5.3 identity, control, event, recovery,
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

## Future V5.3 repository control contract

Everything in this section is frozen future scope. PR1 does not implement it.

### One repository authority

Each repository has one versioned `repo_control` v2 object. Its conditional
write is the only repository semantic commit point. V2 removes `manifest.pb`
and every other mutable authority. A policy object, settings object, bundle
list, LFS catalog, event record, capacity shard, lease, host index, or recovery
record cannot independently publish repository-visible state or authorize a
mutation.

`repo_control` contains the complete bounded WAL and control state needed for a
normal read. It contains immutable identity, lifecycle, visibility, durable
roots, grants and authorization epoch, writer holder and epoch, finite quota
and charged usage, capacity binding, unresolved receipts, reclamation state,
and the last internal mutation identity. Large collections use immutable
catalog pages. A catalog becomes authoritative only when an exact root is
published by the `repo_control` CAS.

The encoded control object is at most 1 MiB. It contains at most 4,096 pack
references, 256 inline WAL-tail entries, and 256 direct grants. Every string,
byte field, catalog root set, and catalog page also has an explicit encoded
size and item bound. The writer compacts before a limit. If compaction cannot
restore the bound, it rejects new work before publication. It never truncates
authority or lets control grow without a bound.

`host_control` is a derived namespace, path, discovery, and routing index. It
does not define repository existence, visibility, authorization, roots, or
writer ownership. A stale or missing host index can affect discovery only.
Direct repository lookup reads `repo_control`.

Immutable payloads and candidate catalog pages can be written before the
control CAS. They remain unreachable and have no semantic effect until that
CAS publishes their exact roots. Every client and system mutator follows this
rule. There is no local fallback and no second publishing key.

### Identity, lifecycle, visibility, and grants

Repository identity is a UUID plus immutable generation 1. Create, recovery,
capability, pin, event, build, cutover, and provider records bind all of these
values:

- opaque tenant ID;
- opaque project ID;
- repository UUID and generation;
- the exact canonical UTF-8 path bytes produced by Cloud Core; and
- the SHA-256 digest of those bytes.

Cloud Core is the only Unicode canonicalizer. Rust treats the supplied bytes
as opaque and compares them with binary equality. A shared adversarial corpus
proves that both implementations accept and reject the same paths. Rename,
move, path reuse, and generation change remain unsupported in the foundation.

Only a signed Cloud Core create intent can create control. It binds identity,
path, object format, initial visibility, finite quota, and the initial
repository-admin grant. It also binds issuer, audience, key ID, intent ID,
issue time, and expiry. One `Create` of `repo_control` makes the candidate
`ACTIVE`. An exact replay is idempotent. A different intent or identity at the
same path fails.

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
comparison across the full configured set. Issued token MAC verification stays
constant-time. Effective settings and every describe or dump surface expose
only an allowlist and never serialize authentication, OAuth, broker, webhook,
store, or session secrets.

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

Ordinary request and maintenance paths cannot delete noncurrent versions. A
writer-fenced typed reclaimer can exact-version-delete a catalog-proven
unreachable version only after receipt, event, capacity, pin, recovery, and
retention obligations expire. It enumerates versions with bounded pagination
and handles delete markers explicitly. Automatic bucket lifecycle rules may
abort abandoned multipart uploads, but they cannot expire protected object
versions. KMS key retention exceeds the maximum retained object-version
horizon.

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
a control-rooted cursor. Candidate classes are closed enums, never caller
prefixes. The protection closure includes current WAL roots, all immutable
catalogs, LFS ownership, pins, event and recovery catalogs, and their exact
versions. Every delete names an expected `ObjectVersionID`. Capacity refunds
only after a verified delete. Identity and control are never reclaimed.

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
tenant, project, repository, generation, and canonical path identity. Errors
remain bounded and never contain credentials or remote response bodies.

## Future capabilities and read authorization

A capability binds tenant, project, repository UUID, generation, purpose,
token identity, authorization epoch, and expiry. Mutations reauthorize against
the exact control version they CAS. New reads check current control visibility,
lifecycle, grants, and authorization epoch. In-flight reads have a bounded
timeout after revocation or deletion.

WalGit does not issue presigned URLs that outlive repository authorization.
LFS upload can stream to an immutable candidate, but finalize reauthorizes and
publishes ownership through the control CAS. Service-build credentials are
separate from user and webhook credentials and enforce full scope and
cancellation checks.

## Future events, fanout, and build pins

The publishing control CAS includes a stable event core with repository UUID,
generation, WAL sequence, mutation ID, and the complete all-ref change set.
The later immutable result envelope adds the successful control
`ObjectVersionID`. `PushEvent` is versioned and preserves current repository,
ref, branch, before, after, commit, pusher, forced, created, deleted, and
compare semantics. Only branch events start builds. Tags and other ref events
remain observable but do not enqueue a build.

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
- exact-version HEAD, GET, and delete; and
- delete-marker behavior and cleanup isolation.

The later production gate proves full-scale object counts, throughput,
retention, event replay and fanout, build pins, restore, cutover, and recovery
on the exact provider and exact production candidate digest.

## Future vertical acceptance

These scenarios are required by later gates. PR1 does not implement them.

- A valid signed create intent creates the exact UUID, generation, path,
  visibility, quota, and initial admin once. Unsigned, altered, expired,
  cross-tenant, cross-project, and replay-conflict requests publish nothing.
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
- Secret and revocation tests cover Git, LFS, API, settings, policy, webhook,
  build, and capability surfaces.
- Bound tests fill control, pack, tail, grant, receipt, catalog, queue, and
  error limits and prove compact-or-reject behavior.
- Exact-provider tests bind the selected endpoint and candidate digest and
  exercise every PR2 primitive plus the later scale and recovery gates.
- Promotion tests prove that production consumes the exact candidate digest
  that passed all evidence, with no rebuild or mutable-tag substitution.
