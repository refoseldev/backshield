# BackShield for Garry's Mod

Server-side defensive library for auditing Lua addons and hardening custom net receivers.

## Installation

Copy the `backshield` directory into `garrysmod/addons/`, then restart the server. Findings are printed to the server console and appended to `garrysmod/data/backshield/events.log`.

BackShield starts in **audit mode**. It does not delete files, ban players, or block dynamic Lua by default.

## Commands

- `backshield_scan` — rescan mounted Lua files (server console or superadmin).
- `backshield_report` — print detailed findings and tracked net receivers.

## Protecting a net receiver

Replace `net.Receive` with `BackShield.Receive` for handlers that accept client input:

```lua
BackShield.Receive("shop.buy", {
    rate = 4,       -- sustained messages per second per player
    burst = 8,      -- short burst capacity
    maxBits = 4096  -- reject larger payloads
}, function(length, ply)
    local itemId = net.ReadUInt(16)
    if not Shop.Items[itemId] then return end
    if not ply:CanAfford(Shop.Items[itemId].price) then return end

    -- Recompute price and permissions on the server. Never trust client values.
    Shop:Buy(ply, itemId)
end)
```

The rate limiter is a token bucket. A protected callback runs inside `xpcall`, so malformed input is logged without breaking the receiver.

## Configuration and allowlisting

Edit `lua/backshield/sh_config.lua`. A specific finding can be suppressed without hiding the whole file:

```lua
IgnoredFindings = {
    ["my_addon/server/sv_loader.lua"] = { "dynamic_code" }
}
```

`BlockDynamicCode = true` blocks calls passing through the global `RunString` and `CompileString` wrappers. This can break legitimate addons and is not a security boundary: code loaded before BackShield can retain original function references. Review the audit log first.

## What the scanner means

Findings are weighted indicators, not proof of malware. Remote/dynamic execution scores more heavily than legitimate-but-sensitive APIs. Minified or obfuscated addons may produce false positives; inspect every high-score file manually.

## Limits

- No generic library can repair authorization mistakes inside arbitrary addon logic.
- A compromised binary module or host account is outside Lua-level protection.
- Existing receivers should be migrated to `BackShield.Receive` and must validate types, ranges, ownership, permissions, entity validity, and server-side prices/state.
- Keep Garry's Mod and addons updated, restrict file/host access, and maintain tested backups.
