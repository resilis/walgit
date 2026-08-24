# Production architecture charter

Status: frozen V4.3 production target. This document separates the first
storage gate from later gates. It does not claim that WalGit is ready for
production.

## Outcome and preserved boundaries

Cloud Core will make a greenfield, zero-data hard cut from Forgejo to WalGit.
The cut requires a signed empty-state check before it changes production.
`git.resilis.io` stays the public Git origin. Existing GitHub integration,
exact-commit builds, tenant isolation, encrypted credential handling, and log
redaction stay unchanged. Cloud Core remains the tenant and orchestration
owner. WalGit owns Git protocol execution and uses one S3-compatible bucket as
its only durable state.

Delivery is producer before consumer and pull-request only. A source pull
request image is never deployable. Cloud Core work starts only after the
required WalGit gates have merged and produced a signed immutable image. This
charter does not authorize a merge, deployment, production bucket access, or
deletion of Forgejo data or storage.

PR1 installs the protected CI and release machinery. It can publish a signed
development/main image only after the named CI workflow succeeds for that
exact protected-main commit. That artifact is supply-chain evidence, not a
production approval, and no PR1 image is deployable. PR3 must still produce
and approve the signed production release image with its required runtime and
recovery evidence before Cloud Core can consume it.

## Gate order

1. **PR1 — storage and preservation evidence (this change).** Freeze the
   behavior matrix. Correct S3 credential loading, declared-length handling,
   multipart bounds and cleanup, retry classification, and conditional
   writes. Add CI and supply-chain evidence. Do not add a durable format.
2. **PR2 — identity and control.** Add repository identity, lifecycle,
   authorization, writer fencing, quotas, capacity reservations, and bounded
   reclamation through the control design below.
3. **PR3 — events and operations.** Add durable event replay/archive,
   exact-commit pins, recovery catalogs and journals, production runtime
   evidence, and the signed release image.
4. **Cloud Core consumer change.** Replace its hosted-Forgejo provider only
   after gates 1–3 are complete.

## PR1 binding storage contract

- The selected S3-compatible bucket is the only durable state. Local disk and
  memory are disposable caches.
- Small mutable metadata uses one atomic conditional write. A caller must get
  an explicit failure when the provider cannot enforce a requested condition.
- Large immutable data stays digest-addressed and streams through bounded
  multipart operations. The design continues to support a 64 GiB receive, a
  16 GiB LFS object, and 30 GiB or larger packs and bundles. It has no 4 GiB
  product limit.
- The AWS SDK default credential chain supplies refreshable credentials.
  Empty explicit override names leave standard AWS environment variables and
  temporary credentials under that chain. Configured custom access and secret
  variables override it only when both contain non-empty values; a configured
  custom session-token variable must also resolve. An incoherent partial
  override is a startup error. Secret values never enter logs or errors.
- Runtime multipart abort is best effort. The production bucket must configure
  `AbortIncompleteMultipartUpload` lifecycle cleanup for uploads left by
  process death or provider outages.
- Endpoint, region, bucket, prefix, and path-style settings remain explicit
  deployment inputs. Memory, GCS, and standalone behavior remain supported.
- The exact production provider must later prove objects larger than 5 GiB,
  the 10,000-part boundary, concurrent conditions, credential rotation,
  multipart cleanup, and conditional completion before a later format gate
  can merge.

## Frozen future control design (not implemented by PR1)

Each repository will have one versioned `repo_control` object as its only
semantic commit point. It will contain immutable identity and generation,
lifecycle and visibility, durable roots, and authorization and writer epochs.
`host_control` will publish namespaces and paths only. The initial repository
control candidate will bind a UUID, generation 1, path, and repository-admin
grant to a signed Cloud Core create intent; one host CAS will make it visible.
Host grants will never authorize repository mutations.

One writer with a durable epoch will serialize client and system mutations,
including revocations. Serving instances will remain read-only and forward
opaque credentials. A stale writer will fail the control CAS. Rename, move,
path reuse, and generation changes are unsupported in the foundation.

Logical repository quotas will be finite. Global physical capacity will use
allocatable capacity-control shards plus computed system and emergency
reserves. Reservations will move from expiring `RESERVED` to non-expiring
`COMMITTING`, bound to the expected control version, writer epoch, mutation,
and byte count, then to repository-control publication and `CHARGED`.
`COMMITTING` can abort only after the expected CAS is impossible. Typed,
bounded reclamation will protect repository identity, canonical Git and LFS
data, and every pin and catalog version.

All-ref, same-sequence event envelopes will become visible with the manifest
control CAS. Replay and archive retention will be at least 30 days. Exact-SHA
pins, archive integrity, and fresh transport HMAC will be separate controls.
Recovery will journal each control mutation from intent through CAS to the
completed object VersionId. A write-fenced catalog will capture a consistent
dependency closure and restore version-addressed objects into a new prefix.
An RTO of four hours is valid only after a provider throughput and sizing
equation passes with two-times headroom. Production writer scratch sizing will
come from fixed-thin, index, and expanded-object peaks, not a fixed guess.

## Hard-cut and recovery boundary

`PREPARED` will fence all Forgejo producers and queues and prove that every
configured database, filesystem, S3 repository, LFS, and artifact store is
empty. A signed `ACTIVE` S3 marker will make the cut one-way. After `ACTIVE`,
operators may revoke Forgejo access and scale it to zero. They must not delete
its database, persistent volumes, or buckets without separate explicit
approval.
