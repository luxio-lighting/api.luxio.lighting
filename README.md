# Luxio API

```sh
npm ci
npm run build
MONGO_URI=mongodb://127.0.0.1:27017/luxio UPDATE_PUBLISH_TOKEN=YOUR_SECRET npm start
```

The Dockerfile builds from this repository alone. `compose.yaml` includes MongoDB for local development.

Firmware updates use a fixed, chip-specific recovery layout exclusively. Both publication and lookup require a `target` matching the chip: `<chip>-recovery-v1` (for example, `esp32s3-recovery-v1`). Missing targets, other layouts, and chip/target mismatches return HTTP 400. Update lookup matches the chip and recovery target exactly; records without that target are never returned. There is no compatibility fallback or automatic conversion of old release records.

`Update` retains a unique `(chip, target, build)` index. Only publish manifests produced for the recovery layout, including all USB installation parts. The firmware repository builds all five profiles described below; each chip returns no update until its recovery package is published.

Run `npm run check` and `npm test` here. Tests use a temporary MongoDB process and keep their local data in `.sdk/`. CI/Docker need only this checkout.

## Firmware matrix

`shared/firmware/targets.json` is the committed snapshot of the firmware repository's `targets.json`; refresh it with that repository's `python3 tools/sync-targets.py`. The supported chip keys are `esp32`, `esp32s3`, `esp32c3`, `esp32c5`, and `esp32c6`. C2/C61 are unavailable with the pinned SDK and return 400 rather than advertising a build that cannot be produced.

Every target uses a complete 4 MB flash layout. Each chip has one `<chip>-recovery-v1` target; no 8 MB layout or migration path is maintained.

One build number can be registered independently for each chip/layout pair. POST /updates checks the exact five-part recovery layout, including chip-specific bootloader offsets, and requires the USB and OTA application hashes to match. Application size is limited to the capacity recorded for that target in the matrix. `minimumFlashSize` defaults to the target requirement when omitted (4 MB for every target); new manifests include it explicitly. Optional per-part `size` fields are checked against partition capacities. The publisher separately fetches and validates image chip IDs and checksums before registration; the API does not fetch remote artifacts.

GET /updates keeps exact chip/target matching and channel filtering. Missing releases return null, never a binary for another ESP32 family. Builds with the same number across families do not collide. Existing S3 recovery records keep working without a database migration.

## Firmware binary storage

`PUT /firmware/<sha256>` accepts `application/octet-stream` with the same bearer `UPDATE_PUBLISH_TOKEN` as update registration. Authentication runs before reading the body. Each nonempty artifact is limited to 8 MiB and stored as BSON binary in `FirmwareBlob`, keyed by its verified SHA-256. Identical uploads are idempotent; existing bytes cannot be overwritten with different content. This stays below MongoDB's 16 MiB document limit without base64 overhead or GridFS.

`GET /firmware/<sha256>` serves the exact binary publicly with Content-Length, CORS, an ETag and immutable caching. Download URLs default to `https://api.luxio.lighting`; set `PUBLIC_URL` when hosting this API elsewhere. No additional storage service or volume is required.

Register an update only after uploading its five parts. For API-hosted URLs, registration verifies that each blob exists, matches its declared size and partition capacity, and carries the correct image chip ID where applicable. Metadata lookup never includes binary data. Retrying an identical registration returns 200; changing an existing chip/target/build returns 409. External HTTPS manifests remain supported. Orphaned uploads are harmless and are not offered to devices until registration succeeds.

## Signed OTA over HTTP

New publications require `signatureVersion: 1`, `keyId: "release-2026"` and a base64 DER ECDSA P-256/SHA-256 `signature`. The API verifies against `src/ota-public-key.json`, matching the public key embedded in main firmware and recovery. The private key exists only in the firmware publisher's `OTA_SIGNING_KEY` secret.

The signed UTF-8 payload has LF separators, decimal integers and a final LF:

```
luxio-ota-v1
<keyId>
<chip>
<target>
<build>
<channel>
<size>
<sha256>
```

Device announcements, update checks and firmware downloads use HTTP. The firmware constructs downloads from its compiled API origin plus `/firmware/<signed sha256>` and verifies the signature and streamed hash before selecting an application to boot. Discovery requests retain their challenge-based device signatures. HTTP does not conceal metadata or prevent a network attacker from suppressing updates.

Keep `PUBLIC_URL` on HTTPS for browser Setup, blob uploads and publication. Serve device POST `/announcements/challenge`, POST `/announcements`, GET `/updates` and GET `/firmware/:sha256` over port 80 without redirects. Publishing clients continue to send the bearer token exclusively over HTTPS. Existing database releases remain readable for old clients; all new publications require signatures. Deploy this API before publishing build 31 or later. No database migration or new server-side secret is needed.
