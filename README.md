# Luxio API

```sh
npm ci
npm run build
MONGO_URI=mongodb://127.0.0.1:27017/luxio UPDATE_PUBLISH_TOKEN=YOUR_SECRET npm start
```

The Dockerfile builds from this repository alone. `compose.yaml` includes MongoDB for local development.

Firmware updates use the fixed recovery loader exclusively. Both publication and lookup require a `target` matching the chip: `<chip>-recovery-v1` (for example, `esp32s3-recovery-v1`). Missing targets, other layouts, and chip/target mismatches return HTTP 400. Update lookup matches the chip and recovery target exactly; records without that target are never returned. There is no compatibility fallback or automatic conversion of old release records.

`Update` retains a unique `(chip, target, build)` index. Only publish manifests produced for the recovery layout, including all USB installation parts. Currently the firmware repository builds the ESP32-S3 recovery package; other chips return no update until a recovery package is published for them.

Run `npm run check` and `npm test` here. Tests use a temporary MongoDB process and keep their local data in `.sdk/`. CI/Docker need only this checkout.
