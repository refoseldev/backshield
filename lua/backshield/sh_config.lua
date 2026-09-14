BackShield = BackShield or {}

BackShield.Config = {
    ScanOnStartup = true,
    ScanDelay = 3,
    MaxFileBytes = 1024 * 1024,
    ReportThreshold = 5,
    LogToData = true,

    -- Audit only by default. Enable only after reviewing the report.
    MonitorDynamicCode = true,
    BlockDynamicCode = false,

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
