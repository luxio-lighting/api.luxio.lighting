# Luxio API

```sh
npm ci
npm run build
MONGODB_URI=mongodb://127.0.0.1:27017/luxio UPDATE_PUBLISH_TOKEN=YOUR_SECRET npm start
```

The Dockerfile builds from this repository alone. `compose.yaml` includes MongoDB for local development.

Update publication accepts `target: "ab-v1"` (legacy/default) or `"esp32s3-recovery-v1"`. Devices request their target; legacy clients omitting it cannot see recovery firmware. Before deploying over an existing database, remove the obsolete `chip_1_build_1` unique index from `Update` after confirming the new `chip_1_target_1_build_1` index exists. This allows the same build number on both layouts. Existing records without a target remain legacy updates.

Run `npm run check` and `npm test` here. Tests use a temporary MongoDB process and keep their local data in `.sdk/`. CI/Docker need only this checkout.
