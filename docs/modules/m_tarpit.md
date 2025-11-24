## m\_kmer\_spam

This optional module detects duplicate private-message spam by fingerprinting
each message with overlapping 4-character *k-mers* and tarpits suspicious
connections before they can blast recipients.

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
5. Every k-mer that trips the early entropy check increments a short-lived reputation counter. Future messages
   containing those fragments can pick up an immediate, per-k-mer delay even if they come from a fresh connection.
6. Optionally, a light fan-out tarpit adds a separate delay that grows with the number of unique recipients a
   connection hits inside a rolling window. High-fanout bots accumulate seconds of penalty even before the
   entropy/reputation checks fire, while one-to-one chats stay unaffected.

The detection is content-agnostic. Obfuscated spam collapses to the same k-mer sets, so bot farms blasting
identical payloads from fresh connections are quickly throttled even when they lean on Unicode tricks.

### Configuration

Add a `<kmerspam>` block to `inspircd.conf`. If you just want a sensible baseline,
start with the **Quick Start** stanza:

```
<kmerspam
    k="4"
    minlength="12"
    early_max_messages="10"
    early_ratio="0.35"
    early_weight="9.2"
    spammy_threshold="0.30"
    tarpit_delay="10s"
    action="delay"
    exemptmodes="CoaA"
    trustedmodes="Vr">
```

That monitors traffic, exempts opers/admins, tarpits suspicious connections for 10 seconds,
and only hard-blocks once you flip `action` to `block` or `gline`. All other knobs fall back to safe defaults.

**Detection knobs**

| Option               | Default | Purpose                                                                    |
| -------------------- | ------- | -------------------------------------------------------------------------- |
| `k`                  | `4`     | Size of each sliding k-mer window (3–6 recommended).                       |
| `minlength`          | `12`    | Ignore messages that normalize below this size.                            |
| `early_max_messages` | `10`    | Only the first *N* normalized messages per connection feed the entropy curve. |
| `early_ratio`        | `0.35`  | Distinct/total k-mer ratio threshold. Early bursts below this value look bot-like. |
| `early_weight`       | `9.2`   | TF/IDF average threshold. Lower values indicate “common” spammy fragments. |
| `spammy_threshold`   | `0.30`  | Fraction of k-mers previously observed in flagged spam. Trips even outside the early window. |
| `kmer_penalty`       | `0s`    | Extra tarpit seconds added per unit of spam reputation for the k-mers in a message (0 disables it). |
| `kmer_penalty_cap`   | `0s`    | Maximum delay the k-mer penalty can add.                                                          |
| `max_cache_size`     | `100000`| Maximum number of cached k-mers before trimming by age.                    |
| `cache_ttl`          | `600`   | Trim k-mers that have not been seen in this window (seconds).              |
| `reputation_ttl`     | `900`   | How long spammy k-mers retain their reputation (seconds).                  |
| `exemptmodes`        | `CoaA`  | Users with any of these modes bypass the filter entirely.                  |
| `trustedmodes`       | `Vr`    | Users with these modes skip inspection (opers, service bots, etc.).        |

**Response knobs**

| Option         | Default | Purpose                                                                                              |
| -------------- | ------- | ---------------------------------------------------------------------------------------------------- |
| `action`       | `delay` | `delay` (tarpit), `block`, `gline`, or `silent`. Delay queues the message and replays it after `tarpit_delay`. |
| `tarpit_delay` | `10s`   | Base delay for each queued message when `action="delay"`.                                            |
| `tarpit_multiplier` | `2.0` | Multiply the delay by this factor if the user is already in the tarpit (ratchets repeat offenders). |
| `fanout_delay` | `0s` | Optional extra delay applied when a connection talks to multiple unique recipients in quick succession. |
| `fanout_multiplier` | `1.0` | Grows the fan-out delay exponentially as the number of unique recipients inside the window increases. |
| `fanout_window` | `30s` | How long a recipient stays in the “recent fan-out” window (set to `0` to disable fan-out tracking). |
| `tarpit_max_delay` | `0` | Optional cap on the per-message delay (0 = unlimited).                                               |
| `gline_duration` | `3600` | Timed G-line length when `action="gline"`.                                                          |

### Operational notes

* Only outbound messages from local users are inspected; remote traffic is assumed to
  be filtered at the origin server.
* The cache is in-memory (~5 MB at the defaults) and resets on restart. Smaller networks can lower `max_cache_size`.
* Review `ircd.log` (look for the `kmerspam` tag) to capture detection metrics (ratios, TF/IDF weights, tarpit hits) before tightening thresholds.

Load the module after compiling:

```
/loadmodule extra/m_kmer_spam
```
