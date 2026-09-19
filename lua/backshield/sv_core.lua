if not SERVER then return end

BackShield = BackShield or {}
local BS = BackShield
local cfg = BS.Config or {}

BS.Version = "1.1.0"
BS.Findings = BS.Findings or {}
BS.NetReceivers = BS.NetReceivers or {}
BS.RateBuckets = BS.RateBuckets or {}

local function now()
    return os.date("!%Y-%m-%dT%H:%M:%SZ")
end

local function rotateLogIfNeeded()
    local size = file.Size("backshield/events.log", "DATA") or 0
    if size < (cfg.MaxLogBytes or 2097152) then return end
    if file.Exists("backshield/events.log.1", "DATA") then
        file.Delete("backshield/events.log.1")
    end
    file.Rename("backshield/events.log", "backshield/events.log.1")
end

-- CAMI (https://github.com/glua/CAMI) is the de-facto standard admin-mod
-- interoperability layer; fall back to IsSuperAdmin when it isn't present.
local function hasAdminAccess(ply)
    if not IsValid(ply) then return true end -- server console
    if CAMI then
        local access = CAMI.PlayerHasAccess(ply, cfg.AdminPrivilege or "BackShield - View Reports", nil)
        if access ~= nil then return access end
    end
    return ply:IsSuperAdmin()
end
BS.HasAdminAccess = hasAdminAccess

if CAMI then
    CAMI.RegisterPrivilege({
        Name = cfg.AdminPrivilege or "BackShield - View Reports",
        MinAccess = "superadmin",
        Description = "View BackShield scan reports and receive its admin alerts."
    })
end

local function notifyAdmins(message)
    if not (cfg.NotifyAdmins ~= false) then return end
    for _, ply in ipairs(player.GetAll()) do
        if hasAdminAccess(ply) then
            ply:ChatPrint("[BackShield] " .. message)
        end
    end
end

local function log(level, message)
    local line = string.format("[%s] [BackShield/%s] %s", now(), level, message)
    MsgC(level == "HIGH" and Color(255, 90, 90) or Color(255, 200, 80), line .. "\n")
    if cfg.LogToData then
        file.CreateDir("backshield")
        rotateLogIfNeeded()
        file.Append("backshield/events.log", line .. "\n")
    end
    if level == "HIGH" then
        notifyAdmins(message)
    end
end

BS.Log = log

local rules = {
    { id = "dynamic_code", score = 4, pattern = "RunString%s*%(", message = "RunString executes dynamic Lua" },
    { id = "dynamic_compile", score = 3, pattern = "CompileString%s*%(", message = "CompileString compiles dynamic Lua" },
    { id = "dynamic_code", score = 4, pattern = "_G%s*%[%s*[\"']Run[\"']%s*%.%.%s*[\"']String[\"']%s*%]", message = "Indexed _G access rebuilding RunString name" },
    { id = "remote_code", score = 8, pattern = "http%.Fetch%s*%([^\n]-RunString", message = "Downloaded content may be executed" },
    { id = "remote_code", score = 8, pattern = "HTTP%s*%([^\n]-RunString", message = "Downloaded content may be executed" },
    { id = "remote_code", score = 8, windowFirst = "http%.Fetch%s*%(", windowSecond = "RunString%s*%(", window = 600, message = "RunString called shortly after http.Fetch; downloaded content may be executed" },
    { id = "remote_code", score = 8, windowFirst = "HTTP%s*%(", windowSecond = "RunString%s*%(", window = 600, message = "RunString called shortly after HTTP(); downloaded content may be executed" },
    { id = "sql_concat", score = 3, pattern = "sql%.Query%s*%([^\n]-%.%.", message = "Concatenated SQL may permit injection" },
    { id = "sql_concat", score = 3, pattern = "sql%.QueryTyped%s*%([^\n]-%.%.", message = "Concatenated SQL may permit injection" },
    { id = "sql_concat", score = 2, pattern = "sql%.Query%s*%([^\n]-string%.format", message = "Formatted SQL may permit injection if values are unescaped" },
    { id = "net_dynamic", score = 6, pattern = "net%.ReadString%s*%(%s*%)[^\n]-RunString", message = "Network input may reach RunString" },
    { id = "net_dynamic", score = 6, windowFirst = "net%.ReadString%s*%(%s*%)", windowSecond = "RunString%s*%(", window = 600, message = "RunString called shortly after net.ReadString; network input may reach it" },
    { id = "console_command", score = 2, pattern = "game%.ConsoleCommand%s*%(", message = "Server console command execution" },
    { id = "binary_module", score = 2, pattern = "require%s*%(", message = "Native/Lua module loading" },
    { id = "obfuscation", score = 3, pattern = "string%.char%s*%([^\n]-string%.char", message = "Repeated string.char may indicate obfuscation" }
}

local function startsWith(value, prefix)
    return string.sub(value, 1, #prefix) == prefix
end

local function ignoredPath(path)
    for _, prefix in ipairs(cfg.IgnoredPathPrefixes or {}) do
        if startsWith(path, prefix) then return true end
    end
    return false
end

local function findingIgnored(path, ruleId)
    local entries = (cfg.IgnoredFindings or {})[path]
    if not entries then return false end
    for _, id in ipairs(entries) do
        if id == ruleId then return true end
    end
    return false
end

local function lineAt(content, offset)
    local _, count = string.gsub(string.sub(content, 1, offset), "\n", "\n")
    return count + 1
end

local function addMatch(result, path, rule, offset)
    if findingIgnored(path, rule.id) then return end
    result.score = result.score + rule.score
    result.matches[#result.matches + 1] = {
        id = rule.id,
        line = lineAt(result.content, offset),
        score = rule.score,
        message = rule.message
    }
end

local function scanPatternRule(result, path, content, rule)
    local from = 1
    while true do
        local first, last = string.find(content, rule.pattern, from)
        if not first then break end
        addMatch(result, path, rule, first)
        from = math.max(last + 1, from + 1)
    end
end

-- Matches when windowSecond occurs within `window` characters after windowFirst,
-- catching multi-line constructs a single-line pattern would miss (e.g. a
-- downloaded payload assigned to a variable and executed a few lines later).
local function scanWindowRule(result, path, content, rule)
    local from = 1
    while true do
        local first, last = string.find(content, rule.windowFirst, from)
        if not first then break end
        local windowEnd = math.min(#content, last + (rule.window or 400))
        local secondFirst = string.find(content, rule.windowSecond, last + 1)
        if secondFirst and secondFirst <= windowEnd then
            addMatch(result, path, rule, first)
        end
        from = last + 1
    end
end

function BS.ScanSource(path, content)
    local result = { path = path, score = 0, matches = {}, content = content }
    if ignoredPath(path) then return result end

    for _, rule in ipairs(rules) do
        if rule.pattern then
            scanPatternRule(result, path, content, rule)
        else
            scanWindowRule(result, path, content, rule)
        end
    end
    result.content = nil
    return result
end

local function walkLua(directory, output)
    local files, directories = file.Find(directory .. "*", "LUA")
    for _, name in ipairs(files or {}) do
        if string.GetExtensionFromFilename(name) == "lua" then
            output[#output + 1] = directory .. name
        end
    end
    for _, name in ipairs(directories or {}) do
        walkLua(directory .. name .. "/", output)
    end
end

-- Cache prior findings per file by size (GMod's file API exposes no mtime
-- for mounted Lua). A changed size always forces a rescan; a same-size
-- edit is rare enough for a periodic scan and is still caught by
-- backshield_scan run right after an update.
BS.FileCache = BS.FileCache or {}

function BS.ScanAll(force)
    local paths = {}
    local findings = {}
    local scanned, cached = 0, 0
    walkLua("", paths)

    local seen = {}
    for _, path in ipairs(paths) do
        seen[path] = true
        local size = file.Size(path, "LUA") or 0
        if size > 0 and size <= (cfg.MaxFileBytes or 1048576) then
            local cache = BS.FileCache[path]
            if not force and cache and cache.size == size then
                cached = cached + 1
                if cache.result.score >= (cfg.ReportThreshold or 5) then
                    findings[#findings + 1] = cache.result
                end
            else
                local content = file.Read(path, "LUA")
                if content then
                    scanned = scanned + 1
                    local result = BS.ScanSource(path, content)
                    BS.FileCache[path] = { size = size, result = result }
                    if result.score >= (cfg.ReportThreshold or 5) then
                        findings[#findings + 1] = result
                    end
                end
            end
        end
    end

    for path in pairs(BS.FileCache) do
        if not seen[path] then BS.FileCache[path] = nil end
    end

    table.sort(findings, function(a, b) return a.score > b.score end)
    BS.Findings = findings
    log("INFO", string.format("scan complete: %d Lua files (%d scanned, %d cached), %d flagged", #paths, scanned, cached, #findings))
    for _, result in ipairs(findings) do
        log(result.score >= (cfg.NotifyThreshold or 8) and "HIGH" or "WARN", string.format("%s score=%d matches=%d", result.path, result.score, #result.matches))
    end
    hook.Run("BackShieldScanComplete", findings)
    return findings
end

if not BS.OriginalNetReceive then
    BS.OriginalNetReceive = net.Receive
    function net.Receive(name, callback)
        local source = debug.getinfo(2, "Sl") or {}
        BS.NetReceivers[string.lower(name)] = {
            name = name,
            source = source.short_src or "unknown",
            line = source.currentline or 0,
            protected = false
        }
        return BS.OriginalNetReceive(name, callback)
    end
end

function BS.Receive(name, options, callback)
    options = options or {}
    local rate = tonumber(options.rate) or (cfg.DefaultRateLimit or {}).rate or 8
    local burst = tonumber(options.burst) or (cfg.DefaultRateLimit or {}).burst or 16
    local maxBits = tonumber(options.maxBits) or 65536
    local buckets = {}
    BS.RateBuckets[string.lower(name)] = buckets

    util.AddNetworkString(name)
    net.Receive(name, function(length, ply)
        if not IsValid(ply) or not ply:IsPlayer() then return end
        if length > maxBits then
            log("HIGH", string.format("oversized net message %s from %s (%d bits)", name, ply:SteamID64(), length))
            return
        end

        local id = ply:SteamID64()
        local t = CurTime()
        local bucket = buckets[id] or { tokens = burst, updated = t, seen = t }
        bucket.tokens = math.min(burst, bucket.tokens + (t - bucket.updated) * rate)
        bucket.updated = t
        bucket.seen = t
        if bucket.tokens < 1 then
            buckets[id] = bucket
            log("WARN", string.format("rate limit: %s from %s", name, id))
            return
        end
        bucket.tokens = bucket.tokens - 1
        buckets[id] = bucket

        local ok, err = xpcall(function() callback(length, ply) end, debug.traceback)
        if not ok then log("HIGH", string.format("receiver %s failed: %s", name, tostring(err))) end
    end)

    local entry = BS.NetReceivers[string.lower(name)]
    if entry then entry.protected = true end
end

hook.Add("PlayerDisconnected", "BackShield.ForgetPlayer", function(ply)
    local id = ply:SteamID64()
    for _, buckets in pairs(BS.RateBuckets) do
        buckets[id] = nil
    end
end)

timer.Create("BackShield.PruneRateBuckets", 300, 0, function()
    local cutoff = CurTime() - 900
    for _, buckets in pairs(BS.RateBuckets) do
        for id, bucket in pairs(buckets) do
            if (bucket.seen or 0) < cutoff then buckets[id] = nil end
        end
    end
end)

local function installDynamicMonitor()
    if not cfg.MonitorDynamicCode then return end
    if BS.DynamicMonitorInstalled then return end
    BS.DynamicMonitorInstalled = true
    local originalRunString = RunString
    local originalCompileString = CompileString

    RunString = function(code, identifier, handleError)
        local source = debug.getinfo(2, "Sl") or {}
        log("HIGH", string.format("RunString by %s:%d identifier=%s bytes=%d", source.short_src or "?", source.currentline or 0, tostring(identifier), #tostring(code)))
        if cfg.BlockDynamicCode then
            if handleError == false then return "Blocked by BackShield" end
            return nil
        end
        return originalRunString(code, identifier, handleError)
    end

    CompileString = function(code, identifier, handleError)
        local source = debug.getinfo(2, "Sl") or {}
        log("WARN", string.format("CompileString by %s:%d identifier=%s bytes=%d", source.short_src or "?", source.currentline or 0, tostring(identifier), #tostring(code)))
        if cfg.BlockDynamicCode then
            if handleError == false then return "Blocked by BackShield" end
            return nil
        end
        return originalCompileString(code, identifier, handleError)
    end
end

concommand.Add("backshield_scan", function(ply)
    if not hasAdminAccess(ply) then return end
    BS.ScanAll(true)
end)

concommand.Add("backshield_report", function(ply)
    if not hasAdminAccess(ply) then return end
    log("INFO", string.format("%d findings; %d tracked net receivers", #BS.Findings, table.Count(BS.NetReceivers)))
    for _, result in ipairs(BS.Findings) do
        print(string.format("[BackShield] %s score=%d", result.path, result.score))
        for _, match in ipairs(result.matches) do
            print(string.format("  line %d +%d [%s] %s", match.line, match.score, match.id, match.message))
        end
    end
    for _, receiver in pairs(BS.NetReceivers) do
        print(string.format("[BackShield/net] %s protected=%s at %s:%d", receiver.name, tostring(receiver.protected), receiver.source, receiver.line))
    end
end)

installDynamicMonitor()

if cfg.ScanOnStartup then
    timer.Simple(tonumber(cfg.ScanDelay) or 3, BS.ScanAll)
end

log("INFO", "loaded v" .. BS.Version .. (cfg.BlockDynamicCode and " (blocking mode)" or " (audit mode)"))
