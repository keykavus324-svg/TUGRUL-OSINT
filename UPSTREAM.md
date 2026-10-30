# Upstream provenance

- Project: OSIRIS
- Repository: https://github.com/simplifaisoul/osiris
- Imported revision: `99f542da645f4e3cbe895d20ea605d1cef2e573c`
- License: MIT; original copyright retained verbatim in `LICENSE`.
- Original README: `docs/OSIRIS-UPSTREAM.md`

This is a source-based derivative, not a clean-room recreation. The Next.js application, MapLibre engine, API routes, OI, RECON, camera integrations and upstream tests are imported from that revision.

## TUĞRUL changes

- Package identity, page title, splash/header brand and Turkish document metadata.
- Türkiye default landing without automatic IP geolocation; upstream visitor/IP analytics removed.
- `src/components/TugrulWorkspace.tsx` and `src/lib/tugrul/*`: regional map controls, locally persisted source-linked analyst notes, JSON export, safe URL validation and restoration tests.
- Nominatim request queue rechecks its deadline because Node timers can wake early; discovered by upstream rate-gap test.
- Arena preview host and development iframe compatibility. Production frame protection retained.

Existing internal `osiris` identifiers, source attribution, protocol/storage keys and many English labels are intentionally retained to avoid breaking integrations. This is not yet a full Turkish translation. Upstream provider access, credentials and separate scanner prerequisites still apply.
