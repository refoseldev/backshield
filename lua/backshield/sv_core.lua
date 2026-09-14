if not SERVER then return end

BackShield = BackShield or {}
local BS = BackShield
local cfg = BS.Config or {}

BS.Version = "1.0.0"
BS.Findings = BS.Findings or {}
BS.NetReceivers = BS.NetReceivers or {}
BS.RateBuckets = BS.RateBuckets or {}

local function now()
    return os.date("!%Y-%m-%dT%H:%M:%SZ")
end

local function log(level, message)
    local line = string.format("[%s] [BackShield/%s] %s", now(), level, message)
    MsgC(level == "HIGH" and Color(255, 90, 90) or Color(255, 200, 80), line .. "\n")
    if cfg.LogToData then
        file.CreateDir("backshield")
        file.Append("backshield/events.log", line .. "\n")
    end
end

BS.Log = log

local rules = {
    { id = "dynamic_code", score = 4, pattern = "RunString%s*%(", message = "RunString executes dynamic Lua" },
    { id = "dynamic_compile", score = 3, pattern = "CompileString%s*%(", message = "CompileString compiles dynamic Lua" },
    { id = "remote_code", score = 8, pattern = "http%.Fetch%s*%([^\n]-RunString", message = "Downloaded content may be executed" },
    { id = "remote_code", score = 8, pattern = "HTTP%s*%([^\n]-RunString", message = "Downloaded content may be executed" },
    { id = "sql_concat", score = 3, pattern = "sql%.Query%s*%([^\n]-%.%.", message = "Concatenated SQL may permit injection" },
    { id = "net_dynamic", score = 6, pattern = "net%.ReadString%s*%(%s*%)[^\n]-RunString", message = "Network input may reach RunString" },
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

function BS.ScanSource(path, content)
    local result = { path = path, score = 0, matches = {} }
    if ignoredPath(path) then return result end

    for _, rule in ipairs(rules) do
        local from = 1
        while true do
            local first, last = string.find(content, rule.pattern, from)
            if not first then break end
            if not findingIgnored(path, rule.id) then
                result.score = result.score + rule.score
                result.matches[#result.matches + 1] = {
                    id = rule.id,
                    line = lineAt(content, first),
                    score = rule.score,
                    message = rule.message
                }
            end
            from = math.max(last + 1, from + 1)
        end
    end
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

function BS.ScanAll()
    local paths = {}
    local findings = {}
    walkLua("", paths)

    for _, path in ipairs(paths) do
        local size = file.Size(path, "LUA") or 0
        if size > 0 and size <= (cfg.MaxFileBytes or 1048576) then
            local content = file.Read(path, "LUA")
            if content then
                local result = BS.ScanSource(path, content)
                if result.score >= (cfg.ReportThreshold or 5) then
                    findings[#findings + 1] = result
                end
            end
        end
    end

    table.sort(findings, function(a, b) return a.score > b.score end)
    BS.Findings = findings
    log("INFO", string.format("scan complete: %d Lua files, %d flagged", #paths, #findings))
    for _, result in ipairs(findings) do
        log(result.score >= 8 and "HIGH" or "WARN", string.format("%s score=%d matches=%d", result.path, result.score, #result.matches))
    end
    hook.Run("BackShieldScanComplete", findings)
    return findings
end

local originalNetReceive = net.Receive
function net.Receive(name, callback)
    local source = debug.getinfo(2, "Sl") or {}
    BS.NetReceivers[string.lower(name)] = {
        name = name,
        source = source.short_src or "unknown",
        line = source.currentline or 0,
        protected = false
    }
    return originalNetReceive(name, callback)
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
    if IsValid(ply) and not ply:IsSuperAdmin() then return end
    BS.ScanAll()
end)

concommand.Add("backshield_report", function(ply)
    if IsValid(ply) and not ply:IsSuperAdmin() then return end
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
