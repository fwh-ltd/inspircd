# Geo Metadata Module

The `m_geo_metadata` module sets IRCv3 metadata keys with geolocation data for users based on their IP address. It uses InspIRCd's geolocation API (provided by modules like `m_geo_maxmind`).

## Loading

```xml
<module name="geo_metadata">
```

This module depends on:
- `ircv3_metadata` for the metadata API
- A geolocation provider module (e.g., `m_geo_maxmind`)

## Configuration

No configuration is required. The module automatically registers and sets the following metadata keys:

| Key | Description | Example |
|-----|-------------|---------|
| `geo/country-code` | ISO 3166-1 alpha-2 country code | `US` |
| `geo/country` | English country name | `United States` |

## How It Works

1. User connects to the IRC server
2. Geolocation module (e.g., `m_geo_maxmind`) looks up user's IP
3. This module reads the location and sets metadata keys
4. Clients with `draft/metadata-2` capability can read the values
5. Metadata is cleared on user disconnect

## Example

**User connects from US IP address:**
```
METADATA nick geo/country-code * :US
METADATA nick geo/country * :United States
```

## Comparison with m_webirc_metadata

| Module | Source | Use Case |
|--------|--------|----------|
| `m_geo_metadata` | Server-side IP lookup | Direct IRC connections |
| `m_webirc_metadata` | Gateway WEBIRC flags | Web client connections |

For web clients behind a gateway, prefer `m_webirc_metadata` with `location/country-code` flags from `webircgateway-geoip`. This avoids duplicate lookups since the gateway already knows the client's real IP.

## Security Considerations

- Metadata keys are registered as `servicesonly`, preventing clients from overwriting them
- Location data is only as accurate as the geolocation database
- Values are cleared on user disconnect
