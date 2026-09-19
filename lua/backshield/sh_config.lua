BackShield = BackShield or {}

BackShield.Config = {
    ScanOnStartup = true,
    ScanDelay = 3,
    MaxFileBytes = 1024 * 1024,
    ReportThreshold = 5,
    LogToData = true,
    MaxLogBytes = 2 * 1024 * 1024, -- rotate events.log to events.log.1 past this size

    -- Audit only by default. Enable only after reviewing the report.
    MonitorDynamicCode = true,
    BlockDynamicCode = false,

    -- Notify admins in chat when a HIGH-severity finding or event occurs.
    NotifyAdmins = true,
    NotifyThreshold = 8,
    -- CAMI privilege checked for admin notifications and console commands.
    -- Falls back to ply:IsSuperAdmin() when CAMI is not installed.
    AdminPrivilege = "BackShield - View Reports",

    DefaultRateLimit = {
        rate = 8,
        burst = 16
    },

    IgnoredPathPrefixes = {
        "backshield/"
    },

    IgnoredFindings = {
        -- ["some/addon/file.lua"] = { "dynamic_code" }
    }
}
