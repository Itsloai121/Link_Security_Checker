# Threat feeds: sources, licences, operation

The blocklist test (#1) and the abuse-network part of the hosting test (#12) use public lists downloaded to the server, so **no checked link leaves your server** for them. The catalogue is `config/defaults/feeds.json`; which feeds run is `UNMASK_ENABLED_FEEDS`.

| Feed (name) | Provides | Licence and conditions (verify at the source, terms can change) |
|---|---|---|
| OpenPhish Community Feed (`openphish`), `https://openphish.com/feed.txt` | Phishing URLs, refreshed about every 12 h | Free for **non-commercial** use only. Commercial deployments need a licence from OpenPhish. Terms: https://openphish.com/terms.html |
| Spamhaus DROP v4 / v6 (`spamhaus_drop`, `spamhaus_drop_v6`) | Hijacked / criminal-controlled IP netblocks | Free of charge; **credit to The Spamhaus Project must accompany use**; JSON lists change daily. Terms: https://www.spamhaus.org/drop/terms |
| Spamhaus ASN-DROP (`spamhaus_asndrop`) | Networks (ASNs) controlled by criminals | Same as above |

Defaults for the Spamhaus JSON URLs follow their published format; confirm the current file names at https://www.spamhaus.org/drop/ and edit `feeds.json` if they have moved. An unreachable or renamed feed shows up as `failed` in `update-feeds --status` and leaves previously loaded data untouched.

**Optional online providers (off by default, key required):** Google Safe Browsing (`UNMASK_GSB_API_KEY`) and URLhaus (`UNMASK_URLHAUS_AUTH_KEY`, free abuse.ch account; URLhaus requires an Auth-Key for API access). Enabling either **sends the URLs being checked to that provider**: update your privacy notice and read their terms.

## Commands
```powershell
python -m interfaces.cli update-feeds              # download all enabled feeds
python -m interfaces.cli update-feeds --status     # what is loaded, when, and the licence notes
python -m interfaces.cli update-feeds --only openphish
python -m interfaces.cli import-feed openphish C:\path\to\feed.txt   # from a local file (offline, manual download)
```

## Safety behaviour
- HTTPS only, size-capped, parsed line by line; unreadable lines are counted, metadata lines ignored.
- **Rejection:** a result with fewer indicators than `min_expected`, or one that would shrink the list by more than 80%, is refused and the old data stays. See `feed_updates` for the history.
- Replacement is atomic: readers see the old list or the new one, never a mixture.
- Until a feed has been downloaded once, the blocklist test reports **"not verified"** (not "clear").

## Adding a feed
Add an entry to `feeds.json` (validated against `config/schemas/feeds.schema.json`): `name`, `title`, `url` (https), `format` (`urls`, `hosts`, `cidr_json_lines`, `cidr_text`, `asn_json_lines`, `asn_text`), `kind`, `category`, `min_expected`, `max_bytes`, `terms`, `terms_url`, `attribution`. Add its name to `UNMASK_ENABLED_FEEDS`. Respect its licence.
