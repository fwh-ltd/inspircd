## m\_gecosjson

This optional module inspects JSON payloads embedded in a user's realname (GECOS),
verifies hashed identity tokens, and optionally scrubs fields for privacy after
the handshake has been validated.

### Features

- Restrict verification to specific connect classes via glob patterns.
- Validate hashed idents (`w<hash>`) and/or JSON fields using a shared salt and
  InspIRCd's hash providers (default: SHA-256).
- Require that certain username patterns (e.g., `kiwi-*`) always present valid
  JSON metadata with a matching hash field.
- Strip selected keys—or the entire JSON blob—from the stored GECOS once the
  metadata has been consumed.

### Configuration

Add the module and its configuration (requires the header-only
[nlohmann/json](https://github.com/nlohmann/json) library):

```
# extra module; build with: ./configure --enable-extras m_gecosjson
<module name="gecosjson">

<gecosjson
    salt="shared-secret"
    mode="both"                # ident, realname, both, or off
    classes="web/*"            # optional connect class filter
    usernamepattern="kiwi-*"   # only enforce JSON for matching idents
    hashkey="ih"               # JSON key that stores the identity hash
    stripfields="sg,tg,cn"     # comma-separated list or "*" to clear all fields
    reason="Invalid identity metadata">
```

| Option            | Description                                                                                         |
| ----------------- | --------------------------------------------------------------------------------------------------- |
| `salt`            | Shared secret combined with the user's IP to generate identity hashes.                              |
| `mode`            | Which checks to enforce: `ident`, `realname`, `both`, or `off` (log-only).                          |
| `classes`         | Space-separated glob patterns of connect class names to inspect; empty = all classes.               |
| `usernamepattern` | Glob pattern of usernames that must provide JSON metadata when `mode=realname` or `both`.           |
| `hashkey`         | JSON field name containing the hashed value to compare against the client IP.                       |
| `stripfields`     | Comma-separated list of JSON keys to remove after verification, or `*` to clear the entire GECOS.   |
| `reason`          | Quit reason when a user fails verification (only enforced when `mode` is not `off`).                |

### Sample metadata migration

If you also need to map JSON fields into `draft/metadata-2` keys for downstream
modules, adapt `docs/conf/gecos_metadata.example.conf` to your deployment. It shows
how you might associate user attributes (gender, country, etc.) with metadata keys
after validation.
