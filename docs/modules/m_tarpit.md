## m\_tarpit

This optional module detects duplicate private-message spam by fingerprinting
each message with overlapping 4-character *k-mers* and tarpits suspicious
connections before they can blast recipients. Version 2 adds rolling stats,
operator presets, and a `/TARPIT` management command.

### How it works

1. Incoming privmsgs/notice tagmsgs to a single user are normalized (lowercased ASCII, zero-width
   code points stripped via [utfcpp](https://github.com/nemtrif/utfcpp), whitespace removed, only `[a-z0-9._-]` kept).
2. The module slices the canonical text into k-mers (default `k=4`) and compares them
   against a short-lived network cache to compute TF/IDF-style weights.
3. Each connection tracks its first few normalized messages. If the distinct/total k-mer ratio
   and the running TF/IDF average both crater within that window—or if the message reuses
   k-mers previously flagged as spam—the connection is considered suspicious.
4. Suspicious senders are tarpitted: their messages are queued and replayed after a configurable delay.
   This is similar to SMTP tarpits/greylisting; spammers burn resources waiting, while legit users only notice
   a short pause. If you prefer, you can switch the action to immediate `block`, `gline`, or `silent drop`.

The detection is content-agnostic. Obfuscated spam collapses to the same k-mer sets, so bot farms blasting
identical payloads from fresh connections are quickly throttled even when they lean on Unicode tricks.

### Configuration

Place your settings in a dedicated include (see [`docs/conf/tarpit.example.conf`](../conf/tarpit.example.conf))
and load it from `inspircd.conf`. Define one `<tarpit level="N">` stanza per preset you care about and mark
exactly one of them with `default="yes"` so it becomes the active bundle after a rehash:

```
<tarpit level="2" default="yes" ...>
<tarpit level="3" default="no" ...>
```

Level 0–4 (monitor → extreme) ship with tuned bundles for delay, fan-out pressure,
and per-k-mer penalties. Override any individual knob inside each `<tarpit>` block (or via
`/TARPIT CONFIG SET`) when you need to fine-tune beyond the preset.

### Preset levels

| Level | Codename | Use when… | Delay / Mult / Max | Spammy / Early ratio | Fan-out (delay × mult, window) | Shared penalty (`kmer_penalty`, `cap`, `min_ratio`, `min_score`) | Reputation TTL |
| ----- | -------- | ---------- | ------------------ | -------------------- | ------------------------------ | ---------------------------------------------------------------- | -------------- |
| 0 | `monitor` | You only want telemetry (almost no penalties). | `1s` / `1.0` / `60s` | `0.90` / `0.70` | disabled | `0.00`, `0s`, `0.95`, `10` | `1200s` |
| 1 | `low` | Background noise or light probing. | `2s` / `1.05` / `120s` | `0.75` / `0.60` | `0.5s ×1.5`, `20s` | `0.02`, `30s`, `0.75`, `5` | `900s` |
| 2 | `medium` | Balanced; good default for mixed networks. | `3s` / `1.10` / `300s` | `0.60` / `0.50` | `1s ×2`, `40s` | `0.05`, `60s`, `0.60`, `3` | `600s` |
| 3 | `high` | Sustained spam runs with light collateral. | `4s` / `1.15` / `300s` | `0.50` / `0.45` | `2s ×3`, `60s` | `0.10`, `90s`, `0.50`, `2` | `450s` |
| 4 | `extreme` | Active incidents (Sybil swarms, mirrored payloads). | `5s` / `1.20` / `300s` | `0.40` / `0.40` | `3s ×4`, `60s` | `0.20`, `120s`, `0.40`, `1` | `300s` |

Each preset also adjusts `early_weight` (from `12.0` down to `9.0`) so the entropy/weight gatelines tighten as you escalate.

**Detection knobs**

| Option               | Default | Purpose                                                                    |
| -------------------- | ------- | -------------------------------------------------------------------------- |
| `k`                  | `4`     | Size of each sliding k-mer window (3–6 recommended).                       |
| `minlength`          | `12`    | Ignore messages that normalize below this size.                            |
| `early_max_messages` | `10`    | Only the first *N* normalized messages per connection feed the entropy curve. |
| `early_ratio`        | `0.35`  | Distinct/total k-mer ratio threshold. Early bursts below this value look bot-like. |
| `early_weight`       | `9.2`   | TF/IDF average threshold. Lower values indicate “common” spammy fragments. |
| `spammy_threshold`   | `0.30`  | Fraction of k-mers previously observed in flagged spam. Trips even outside the early window. |
| `max_cache_size`     | `100000`| Maximum number of cached k-mers before trimming by age.                    |
| `cache_ttl`          | `600`   | Trim k-mers that have not been seen in this window (seconds).              |
| `reputation_ttl`     | preset  | How long spammy k-mers retain their reputation (seconds).                  |
| `warmup_observations`| `5000`  | Skip penalising until the module has inspected this many messages (prevents cold-start false positives). |
| `exemptmodes`        | `CoaA`  | Users with any of these modes bypass the filter entirely.                  |
| `trustedmodes`       | `Vr`    | Users with these modes skip inspection (opers, service bots, etc.).        |

**Response knobs**

| Option            | Default | Purpose |
| ----------------- | ------- | ------- |
| `action`          | `delay` | `delay`, `block`, `gline`, or `silent`. |
| `tarpit_delay`    | preset  | Base delay per message. |
| `tarpit_multiplier` | preset | Multiply the delay if the user is already queued. |
| `tarpit_max_delay`  | preset | Drop the message once the computed delay reaches this cap. |
| `fanout_delay/multiplier/window` | preset | Extra delay when a connection targets multiple recipients quickly. |
| `kmer_penalty`, `kmer_penalty_cap`, `kmer_penalty_min_ratio`, `kmer_penalty_min_score` | preset | Shared-state penalty carried between Sybil connections. |
| `gline_duration`  | `3600`  | Timed G-line when `action="gline"`. |

### Operational notes

* Only outbound messages from local users are inspected; remote traffic is assumed to
  be filtered at the origin server.
* Define one `<tarpit level="N">` stanza per preset and flip between them at runtime
  with `/TARPIT CONFIG SET level <N>`. The stanza marked `default="yes"` is applied on rehash.
* The cache is in-memory (~5 MB at the defaults) and resets on restart. Smaller networks can lower `max_cache_size`.
* Review `ircd.log` (look for the `m_tarpit` tag) to capture detection metrics (reasons, delays, drops) before tightening thresholds.
* `/TARPIT` is available to opers:
  * `STATS [seconds]` — dump global totals plus a rolling window (default 300s) grouped by reason.
  * `CONFIG GET [key]` — display the current preset and/or an individual knob (e.g., `kmer_penalty`).
  * `CONFIG SET level <0-4>` — snap to a preset. Any other key/value pair overrides the live state until rehash.
  Changes are announced to the global `a` snomask for auditability.
* A canned configuration lives in `docs/conf/tarpit.example.conf`. Copy it, tweak the defaults, and include it from `inspircd.conf`.

Load the module after compiling:

```
/loadmodule extra/m_tarpit
```
