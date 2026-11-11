# Local API

The upload page is served by a small HTTP server (`python3 -m vulnflow serve`). Its routes are for
the page itself and for local experiments; there is no stable public API and no authentication
beyond the checks below. Do not expose it as a remote or multi-user service.

Every request must be addressed to `127.0.0.1`, `localhost` or `[::1]` (or the access-token link
printed with `--allow-remote`). Every `POST` must come from the same origin and carry the page's
CSRF token: a `csrf` form field, a `csrf` JSON field, or an `X-CSRF-Token` header for `ask`.

| Method and path | Purpose |
| --- | --- |
| `GET /` | The upload page. |
| `POST /analyze-folder` | Analyzes a folder in place. Form fields: `path`, optional `internal_nets`. |
| `POST /analyze` | Analyzes uploaded files (multipart: `telemetry`, `scans`, `ioc_archive`, optional `internal_nets`). |
| `POST /browse` | Lists the subfolders of `path` for the in-page folder picker. |
| `POST /pick-folder` | Opens the macOS Choose Folder dialog (native runs on a Mac only). |
| `POST /locate-folder` | Finds a folder picked in the browser among the shared folders, from its `name` and sample file names, sizes and times. |
| `GET /settings`, `POST /settings` | Security Assistant provider, model, endpoint, key and redaction. |
| `GET /branding`, `POST /branding` | Branding page and its changes (name prefix, logo, logo size). |
| `POST /branding/unlock`, `POST /branding/lock` | Unlocks the Branding page with its password, or locks it again. |
| `GET /runs/<id>/` | Results page for a run; other paths under it serve that run's reports. |
| `GET /runs/<id>/ai-status` | Whether a Security Assistant provider is ready, and where data goes. |
| `POST /runs/<id>/brief` | Writes the Security Assistant brief for the run. |
| `POST /runs/<id>/ask` | Asks the Security Assistant a question (JSON). |
| `POST /runs/<id>/article-briefs` | Generates OpenAI article briefs for matched source articles. |
| `GET /runs/<id>/radar-status` | Whether a Cloudflare Radar token is configured. |
| `POST /runs/<id>/radar` | Looks up one matched IP or domain IOC on Cloudflare Radar (JSON `type`, `value`). |

Run IDs are 16 hex characters. Paths under `/runs/<id>/` are confined to that run's output folder.
A second analysis while one is running is refused with a message rather than queued.

## Analyze a folder

```sh
# The CSRF token is embedded in the upload page; a browser session is the supported client.
curl -s http://127.0.0.1:8080/ | grep -o 'name="csrf" value="[^"]*"'
```

For scripted runs, prefer the command line, which needs no server:

```sh
python3 -m vulnflow analyze /path/to/case -o out --internal-net 10.0.0.0/8
```

See [methods and limits](METHODS.md) for input formats, privacy and outbound network use.
