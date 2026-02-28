# API Scanner Backend (MVP)

This service runs scans server-side as queued jobs.

## Run

```bash
cd backend
npm install
npm run dev
```

Server: `http://localhost:8787`

## Endpoints

- `GET /health`
- `POST /api/v1/scans`
- `GET /api/v1/scans`
- `GET /api/v1/scans/:id`
- `POST /api/v1/scans/:id/cancel`

## Request example

`POST /api/v1/scans`

```json
{
  "targets": ["https://example.com"],
  "options": {
    "scanAssets": true,
    "checkHeaders": true,
    "checkExposed": true,
    "entropyThreshold": 3.5,
    "maxMatchesPerRule": 8
  }
}
```

## Notes

- Uses in-memory job storage (resets on restart).
- Active exploit-style tests are not enabled in this MVP backend.
- Only scan systems you own or have explicit permission to test.
