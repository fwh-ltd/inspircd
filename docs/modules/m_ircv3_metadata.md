# IRCv3 Metadata Module

The `m_ircv3_metadata` module implements the IRCv3 [`draft/metadata-2`](https://ircv3.net/specs/client-tags/metadata.html) capability. It lets users and channels store arbitrary key/value metadata, subscribe to keys, and synchronise values during registration, channel joins, and explicit `METADATA` requests.

## Loading

```
<module name="ircv3_metadata">
```

The module depends on `ircv3_batch`, `ircv3_capnotify`, `ircv3_ctctags`, and `ircv3_replies` to provide batching, cap negotiation, message tags, and Standard Replies. If you load `ircv3_metadata` via `modules.conf.example` you almost certainly want the rest of the IRCv3 stack enabled as well.

## Configuration

Global behaviour is tuned with a single `<ircv3metadata>` block:

```
<ircv3metadata
    beforeconnect="yes"
    allowunknownkeys="yes"
    maxsubs="64"
    maxkeys="32"
    maxvaluebytes="4096"
    autosyncthreshold="200"
    syncretry="60"
    ratelimitrequests="20"
    ratelimitwindow="30"
    defaultscope="both"
    defaultvisibility="*"
    defaultoperonly="no"
    defaultservicesonly="no"
    defaultsetpriv=""
    defaultviewpriv="">
```

### Attribute reference

| Attribute            | Description |
|----------------------|-------------|
| `beforeconnect`      | Allow unregistered users to issue `METADATA * ...` before completing registration. The server batches any values they set and replays them automatically once the capability is enabled. |
| `allowunknownkeys`   | If `yes`, clients may set vendor/private keys that are not listed in `<ircv3metadatakey>` blocks. When `no`, only explicitly whitelisted keys are accepted. |
| `maxsubs`            | Maximum number of keys a user may subscribe to. Exceeding this limit results in `FAIL METADATA TOO_MANY_SUBS`. |
| `maxkeys`            | Maximum number of self-metadata keys a user may store on their own nickname. (Channel keys are governed by channel permissions.) |
| `maxvaluebytes`      | Maximum length, in bytes, for any value supplied via `METADATA SET`. Longer values are rejected with `FAIL METADATA VALUE_INVALID`. |
| `autosyncthreshold`  | If a registration burst or `SYNC` would deliver more than this many entries for a target (channel + members), the server sends `RPL_METADATASYNCLATER` instead of an enormous batch. Clients should retry later via `METADATA <target> SYNC`. Set to `0` to always send the batch. |
| `syncretry`          | Number of seconds clients should wait before reissuing a deferred `SYNC`. This value becomes the `<retry-after>` parameter in `RPL_METADATASYNCLATER` and doubles as the default when rate-limiting kicks in. |
| `ratelimitrequests`  | Requests allowed per-user within each `ratelimitwindow`. The limit applies to GET/LIST/SET/CLEAR/SUB/SUBS/SYNC. Once exceeded, clients receive `FAIL METADATA RATE_LIMITED <target> <key> <retry>`. |
| `ratelimitwindow`    | Window size, in seconds, for the request limiter. |
| `defaultscope`       | Default scope for keys (`user`, `channel`, or `both`) when `<ircv3metadatakey>` does not override it. |
| `defaultvisibility`  | Default visibility tag (the third parameter in METADATA messages). |
| `defaultoperonly`    | If `yes`, unknown keys inherit the requirement that only operators may set them. |
| `defaultservicesonly`| If `yes`, unknown keys default to `servicesonly` (i.e., only services or modules with `users/metadata/service` may set them). |
| `defaultsetpriv` / `defaultviewpriv` | Default InspIRCd privilege strings required to set or view unknown keys. Leave empty to inherit the standard behaviour. |

### Whitelisted keys

Use `<ircv3metadatakey>` blocks to define first-party keys and override the defaults above:

```
<ircv3metadatakey
    name="example/key"
    scope="user"
    visibility="@"
    operonly="no"
    servicesonly="yes"
    setpriv="users/metadata/service"
    viewpriv="users/auspex">
```

`scope` accepts `user`, `channel`, `both`, or `*`. `visibility` is free-form (e.g., `*`, `@`, `+`). The `setpriv`/`viewpriv` attributes are standard InspIRCd privilege strings (see `opers.conf.example` for common names).

## Services integration

Services packages (e.g., Anope, custom bots, or other InspIRCd modules) can reserve keys or intercept updates via the `ircv3metadata` API:

```c++
#include "modules/ircv3_metadata.h"

class ModuleServicesMetadata : public Module, public IRCv3::Metadata::EventListener
{
	IRCv3::Metadata::API metadataapi;

 public:
	ModuleServicesMetadata() : IRCv3::Metadata::EventListener(this), metadataapi(this) {}

	void ReadConfig(ConfigStatus&) override
	{
		if (!metadataapi)
			throw ModuleException("ircv3metadata API is unavailable");

		IRCv3::Metadata::KeySpec spec;
		spec.name = "services/account-name";
		spec.targets = IRCv3::Metadata::TARGET_USER;
		spec.servicesonly = true;
		spec.setpriv = "users/metadata/service";
		spec.viewpriv = "users/auspex";
		metadataapi->RegisterKey(this, spec);
	}

	ModResult OnPreMetadataSet(LocalUser* user, const IRCv3::Metadata::TargetInfo& target,
		const std::string& key, std::string& value, bool removing) override
	{
		if (key != "services/account-name")
			return MOD_RES_PASSTHRU;

		// Only services (or opers with users/metadata/service) may touch this key.
		return user->HasPrivPermission("users/metadata/service") ? MOD_RES_PASSTHRU : MOD_RES_DENY;
	}

	void OnMetadataChanged(User* setter, const IRCv3::Metadata::TargetInfo& target,
		const std::string& key, const std::string& value, bool removing) override
	{
		// React to updates (e.g., sync to services backend).
	}
};
```

The tree ships with `m_services_metadata.cpp`, a concrete implementation that listens to InspIRCd’s account events and mirrors them into the `services/account-name` metadata key. When the module is loaded:

- Logging into services triggers `METADATA <nick> SET services/account-name :<account>`.
- Logging out emits `METADATA <nick> SET services/account-name` (with no value) so capable clients learn about the logout.
- Remote updates (e.g., spanningtree bursts) feed back into InspIRCd’s `accountname` extension so oper tools stay consistent.

You can treat that module as a blueprint for deeper integrations (e.g., storing channel metadata, enforcing key ownership, or syncing to external databases).

## Runtime behaviour

- **Capability tokens** — The module advertises `draft/metadata-2` along with `max-subs`, `max-keys`, `max-value-bytes`, and `before-connect` when enabled.
- **Rate limiting** — When the per-user request budget is exceeded the server sends `FAIL METADATA RATE_LIMITED <target> <key> <retry>` and ignores the command.
- **Deferred sync** — Channel joins/`SYNC` requests that would exceed `autosyncthreshold` produce `RPL_METADATASYNCLATER <target> <retry>`. Clients should reissue `METADATA <target> SYNC` after `<retry>` seconds.
- **Subscriptions** — Successful `METADATA SUB` replies now include the current values for the user, channels they occupy, and channel members where the key is visible, so clients do not need to issue an immediate `SYNC`.
- **Netburst** — During server bursts the module serialises all known user/channel metadata via the standard `METADATA` command, so relinking servers receive consistent state without requiring services replays.

## Logging and diagnostics

- Metadata changes (SET/CLEAR) are broadcast to interested clients via the `METADATA` server message.
- Rate-limit hits and deferrals produce Standard Replies (`FAIL ... RATE_LIMITED`, `RPL_METADATASYNCLATER`) that can be inspected with `/QUOTE`.
- Services modules can hook `event/ircv3-metadata` to log or veto sensitive keys.

## Anope integration notes

We are extending the downstream Anope deployment (`../anope-2.0`, branch `feat/insp4-ircv3-metadata`) so it can mirror BuddyBoss / WordPress profile fields into IRCv3 metadata. The design mirrors the SQL authentication connector: define per-field mappings that run SQL when metadata changes.

```
field {
    name = "bb/cn"  # channel name (BuddyBoss profile field id 5)
    set_query = "INSERT INTO wp_bp_xprofile_data (user_id, field_id, value, last_updated)
                 VALUES (@user_id@, 5, @value@, NOW())
                 ON DUPLICATE KEY UPDATE value=@value@, last_updated=NOW()"
    get_query = "SELECT value FROM wp_bp_xprofile_data WHERE user_id=@user_id@ AND field_id=5"
    result_column = "value"
    sync_on_login = true
    local_only = false
}
```

Implementation details to keep in mind when we resume work:

- `@user_id@` expands to the BuddyBoss/WordPress user id returned by the existing SQL auth connector; the lookup happens when the IRC account identifies.
- `@value@`, `@account@`, and `@nick@` substitutions mirror what SQLAuth already exposes (so field modules can reuse the escaping utilities there).
- Multi-statement queries are avoided; instead, use `INSERT ... ON DUPLICATE KEY UPDATE` style upserts as shown above.
- When no row exists, the connector runs the `INSERT` branch; updates reuse the same query, so BuddyBoss xprofile data stays in sync without additional logic.
- `sync_on_login = true` triggers a `METADATA SET <nick> bb/...` burst right after NickServ identifies, ensuring clients learn about BuddyBoss-side edits even if no metadata change originated from IRC.
- `local_only` should stay `false` so writes reach the external database rather than InspIRCd’s in-memory store.

Outstanding TODOs for this project:

1. Finalise the substitution list and document it in Anope’s README (covering `@user_id@`, `@value@`, `@account@`, etc.).
2. Decide whether field definitions can request bi-directional sync (populate metadata from BuddyBoss on connect) and how to rate-limit it.
3. Wire the new Anope module so it listens for InspIRCd `METADATA` events (via `m_ircv3_metadata`) and calls the SQL helpers above.
4. Provide a sample services.conf snippet mirroring the `field { ... }` block for `bb/cn`, `bb/sg`, and `bb/tg`.

## Example workflow

```
> CAP REQ :draft/metadata-2
< :server CAP * ACK :draft/metadata-2=max-subs=64,max-keys=32,...
> METADATA * SUB display-name
< :server 770 nick display-name
< @batch=1 :server METADATA nick display-name * :Example Name

> METADATA #chat SYNC
< :server RPL_METADATASYNCLATER #chat 45    (channel was too large; retry later)
```
