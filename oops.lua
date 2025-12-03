-- SH_Service Lua Client V2 (hardened)
-- - Anti-debug: timing, pairs/next, global mutate, metatable lock
-- - Dùng với Node.js server V2 (/api/auth)

local Http = game:GetService("HttpService")
local Analytics = game:GetService("RbxAnalyticsService")

-- ĐỔI THÀNH IP/DOMAIN + PORT CỦA BẠN
local API_BASE = "http://217.154.114.227:9971/api"

-- cố gắng tìm hàm request của executor
local requestFunc = request
    or http_request
    or (http and http.request)
    or (syn and syn.request)

if not requestFunc then
    error("SH_Service: no HTTP request function found (request/http_request/syn.request)")
end

local bit = bit32 or bit

-- XOR thuần Lua (fallback nếu không có bit32)
local function bxor(a, b)
    if bit and bit.bxor then
        return bit.bxor(a, b)
    end
    local res, pow = 0, 1
    while a > 0 or b > 0 do
        local abit = a % 2
        local bbit = b % 2
        if abit ~= bbit then
            res = res + pow
        end
        a = (a - abit) / 2
        b = (b - bbit) / 2
        pow = pow * 2
    end
    return res
end

local function getHWID()
    local ok, id = pcall(function()
        return Analytics:GetClientId()
    end)
    if ok and id then
        return id
    end
    return "UNKNOWN_" .. tostring(math.random(100000, 999999))
end

local function randomNonce(len)
    len = len or 32
    local chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    local out = table.create(len)
    for i = 1, len do
        local idx = math.random(1, #chars)
        out[i] = string.sub(chars, idx, idx)
    end
    return table.concat(out)
end

-- snapshot một số global để sau này so sánh
local originalGlobals = {
    pairs = pairs,
    next = next,
    pcall = pcall,
    task_spawn = task and task.spawn,
    coroutine_wrap = coroutine and coroutine.wrap,
}

-- timing anti-debug (detect breakpoint / step)
local function timingProbe()
    local loops = 3
    local total = 0
    for n = 1, loops do
        local t0 = tick()
        local acc = 0
        for i = 1, 200000 do
            acc = acc + i
        end
        local dt = tick() - t0
        total = total + dt
    end
    local avg = total / loops
    -- threshold rộng cho máy yếu
    return avg < 0.8, avg
end

-- kiểm tra behaviour pairs/next
local function checkPairsNext()
    local t = { a = 1, b = 2, c = 3, d = 4 }
    local pc, nc = 0, 0
    local px, nx = 0, 0

    for k, v in pairs(t) do
        pc = pc + 1
        px = bxor(px, string.byte(k) + v)
    end

    for k, v in next, t do
        nc = nc + 1
        nx = bxor(nx, string.byte(k) + v)
    end

    return pc == 4 and nc == 4 and px == nx
end

-- check một số global không bị biến thành string/number
local function checkGlobalsType()
    local env = getfenv and getfenv() or _G

    local function check(name)
        local v = env[name]
        local t = type(v)
        if t == "nil" then
            return true -- có thể không tồn tại trong 1 số executor
        end
        if t == "string" or t == "number" or t == "boolean" then
            return false
        end
        return true
    end

    if not check("pairs") then return false, "GLOBAL_MUTATED" end
    if not check("next") then return false, "GLOBAL_MUTATED" end
    if not check("pcall") then return false, "GLOBAL_MUTATED" end
    return true
end

-- so sánh tham chiếu lúc load script
local function checkOriginalRefs()
    if originalGlobals.pairs and originalGlobals.pairs ~= pairs then
        return false, "GLOBAL_PAIRS_CHANGED"
    end
    if originalGlobals.next and originalGlobals.next ~= next then
        return false, "GLOBAL_NEXT_CHANGED"
    end
    if originalGlobals.pcall and originalGlobals.pcall ~= pcall then
        return false, "GLOBAL_PCALL_CHANGED"
    end
    if originalGlobals.task_spawn and task and originalGlobals.task_spawn ~= task.spawn then
        return false, "GLOBAL_TASK_CHANGED"
    end
    if originalGlobals.coroutine_wrap and coroutine and originalGlobals.coroutine_wrap ~= coroutine.wrap then
        return false, "GLOBAL_COROUTINE_CHANGED"
    end
    return true
end

-- test metatable lock (nếu vẫn sửa được => môi trường bị can thiệp lạ)
local function checkMetatableLock()
    local t = {}
    setmetatable(t, { __metatable = "LOCKED" })
    local ok, _ = pcall(setmetatable, t, {})
    return not ok
end

local function antiDebug()
    local okTime, avg = timingProbe()
    if not okTime then
        return false, "TIMING_DEBUG"
    end

    if not checkPairsNext() then
        return false, "ENV_HOOKED"
    end

    local okType, errType = checkGlobalsType()
    if not okType then
        return false, errType
    end

    local okRefs, errRefs = checkOriginalRefs()
    if not okRefs then
        return false, errRefs
    end

    if not checkMetatableLock() then
        return false, "MT_UNLOCKED"
    end

    return true
end

local function authSH()
    local key = getgenv().SH_Service_Key
    if type(key) ~= "string" or #key < 5 then
        print("Auth Failed:", "INVALID_LOCAL_KEY")
        return false
    end

    local okAnti, reason = antiDebug()
    if not okAnti then
        print("Auth Failed:", reason)
        return false
    end

    local nonce = randomNonce(32)
    local hwid = getHWID()

    local resp
    local okReq = pcall(function()
        resp = requestFunc({
            Url = API_BASE .. "/auth",
            Method = "POST",
            Headers = {
                ["Content-Type"] = "application/json"
            },
            Body = Http:JSONEncode({
                key = key,
                hwid = hwid,
                nonce = nonce
            })
        })
    end)

    if not okReq or not resp or not resp.Body then
        print("Auth Failed:", "REQUEST_ERROR")
        return false
    end

    local data
    local okJson = pcall(function()
        data = Http:JSONDecode(resp.Body)
    end)
    if not okJson or type(data) ~= "table" then
        print("Auth Failed:", "BAD_JSON")
        return false
    end

    if data.status == "AUTH_OK" then
        print("Auth")
        -- Nếu muốn dùng token sau này:
        -- getgenv().SH_Service_Token = data.token
        return true, data
    else
        print("Auth Failed:", data.status)
        return false, data
    end
end

return authSH
