## m\_kmer\_spam

This optional module detects duplicate private-message spam by fingerprinting
each message with overlapping 4-character *k-mers*.

### How it works

1. Incoming privmsgs/tagmsgs to a user are normalized (lowercased ASCII, zero-width
   code points stripped via [utfcpp](https://github.com/nemtrif/utfcpp), whitespace removed, only `[a-z0-9._-]` kept).
2. The module slices the canonical text into k-mers (default `k=4`) and compares them
   against a short-lived network cache.
3. An exponential trust curve raises the acceptable E-value threshold for long-lived
   or privileged users (`+V` trusted, `+C`/opers effectively exempt).
4. When the calculated E-value falls below the trust threshold the message is blocked,
   optionally followed by an automatic G-line.

The detection is content-agnostic: obfuscated messages collapse to the same k-mer
set, so bot farms blasting identical payloads from fresh connections are quickly
flagged even if they lean on Unicode tricks.

### Configuration

Add a `<kmerspam>` block to `inspircd.conf`:

```
<kmerspam
    k="4"
    minlength="10"
    threshold_min="0.001"
    threshold_max="0.1"
    tau="600"
    max_cache_size="100000"
    cache_ttl="600"
    min_observations="1000"
    exemptmodes="CoaA"
    trustedmodes="Vr"
    trusted_multiplier="5.0"
    action="block"           # block, gline, or silent
    gline_duration="3600">
```

| Option              | Default | Purpose                                                                    |
| ------------------- | ------- | -------------------------------------------------------------------------- |
| `k`                 | `4`     | Size of each sliding k-mer window (3–6 recommended).                        |
| `minlength`         | `10`    | Ignore messages that normalize below this size (too short to fingerprint). |
| `threshold_min`     | `0.001` | Starting E-value threshold for new connections.                             |
| `threshold_max`     | `0.1`   | Ceiling threshold for long-lived users.                                     |
| `tau`               | `600`   | Trust decay constant (seconds).                                            |
| `max_cache_size`    | `100000`| Maximum number of cached k-mers before trimming by age.                     |
| `cache_ttl`         | `600`   | Expire entries that have not been observed within this window (seconds).    |
| `exemptmodes`       | `CoaA`  | Users with any of these user modes (e.g., creator/oper/admin) bypass the filter entirely. |
| `trustedmodes`      | `Vr`    | Users with any of these modes get their threshold multiplied by `trusted_multiplier`. |
| `trusted_multiplier`| `5.0`   | Factor applied to trusted users’ threshold (capped at 1.0).                |
| `min_observations`  | `1000`  | Minimum cached k-mer observations before detection activates (prevents cold-start false positives). |
| `action`            | `block` | `block` sends an error, `gline` additionally glines, `silent` drops quietly.|
| `gline_duration`    | `3600`  | Timed G-line length when `action="gline"`.                                 |

### Operational notes

* Only outbound messages from local users are inspected; remote traffic is assumed to
  be filtered at the origin server.
* The cache is in-memory and resets on restart; it represents roughly ~5 MB at the
  default settings.
* Review `ircd.log` (look for the `kmerspam` tag) to monitor detections or tune thresholds.

Load the module after compiling:

```
/loadmodule extra/m_kmer_spam
```
