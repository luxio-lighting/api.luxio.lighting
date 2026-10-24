# Luxio API

```sh
npm ci
npm run build
MONGO_URI=mongodb://127.0.0.1:27017/luxio UPDATE_PUBLISH_TOKEN=YOUR_SECRET npm start
```

The Dockerfile builds from this repository alone. `compose.yaml` includes MongoDB for local development.

Firmware updates use a fixed, chip-specific recovery layout exclusively. Both publication and lookup require a `target` matching the chip: `<chip>-recovery-v1` (for example, `esp32s3-recovery-v1`). Missing targets, other layouts, and chip/target mismatches return HTTP 400. Update lookup matches the chip and recovery target exactly; records without that target are never returned. There is no compatibility fallback or automatic conversion of old release records.

`Update` retains a unique `(chip, target, build)` index. Only publish manifests produced for the recovery layout, including all USB installation parts. The firmware repository builds all five targets listed below; each chip returns no update until its recovery package is published.

Run `npm run check` and `npm test` here. Tests use a temporary MongoDB process and keep their local data in `.sdk/`. CI/Docker need only this checkout.

## Firmware matrix

`shared/firmware/targets.json` is the committed snapshot of the firmware repository's `targets.json`; refresh it with that repository's `python3 tools/sync-targets.py`. The supported chip keys are `esp32`, `esp32s3`, `esp32c3`, `esp32c5`, and `esp32c6`. C2/C61 are unavailable with the pinned SDK and return 400 rather than advertising a build that cannot be produced.

One build number can be registered independently for each chip. POST /updates checks the exact five-part recovery layout, including chip-specific bootloader offsets, and requires the USB and OTA application hashes to match. Application size is limited to the capacity recorded for that target in the matrix. `minimumFlashSize` defaults to the target requirement when omitted (4 MB for ESP32/S3/C3; 8 MB for C5/C6); new manifests include it explicitly. Optional per-part `size` fields are checked against partition capacities. The publisher separately fetches and validates image chip IDs and checksums before registration; the API does not fetch remote artifacts.

GET /updates keeps exact chip/target matching and channel filtering. Missing releases return null, never a binary for another ESP32 family. Builds with the same number across families do not collide. Existing S3 recovery records keep working without a database migration.
