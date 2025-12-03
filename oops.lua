-- SH_Service Lua Client V4
-- - Anti-debug / anti-tamper
-- - Anti HTTP spy (detect Lua wrappers on request/http_request/syn.request/http.request)
-- - HTTP-layer encryption (blob) với XOR + Base64
-- - Verify token: check code, hwidHash, inner HMAC (HKDF + HMAC-SHA1)

local Http = game:GetService("HttpService")
local Analytics = game:GetService("RbxAnalyticsService")

-- ĐỔI THÀNH IP/DOMAIN + PORT CỦA BẠN
local API_BASE = "http://217.154.114.227:9971/api"

-- Secret lớp HTTP phải trùng với HTTP_LAYER_SECRET bên Node
local HTTP_LAYER_SECRET = "SH_HTTP_LAYER_2025_SECURE"

-- Tìm hàm request của executor
local requestFunc = request
    or http_request
    or (http and http.request)
    or (syn and syn.request)

if not requestFunc then
    error("SH_Service: no HTTP request function (request/http_request/syn.request/http.request)")
end

local bit = bit32 or bit
if not bit then
    error("SH_Service: bit32/bit library not found (required for crypto)")
end

local band = bit.band
local bor  = bit.bor
local bxor = bit.bxor
local bnot = bit.bnot or function(a) return ~a end
local lshift = bit.lshift
local rshift = bit.rshift

-- ========== Helpers ==========

local function getHWID()
    local ok, id = pcall(function()
        return Analytics:GetClientId()
    end)
    if ok and id then
        return id
    end
    return "FALLBACK_" .. tostring(math.random(100000, 999999))
end

local function randomNonce(len)
    len = len or 32
    local chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    local out = table.create(len)
    local sum = 0
    for i = 1, len do
        local idx = math.random(1, #chars)
        local ch = string.sub(chars, idx, idx)
        out[i] = ch
        sum = sum + string.byte(ch)
    end
    local mean = sum / len
    if mean < 40 or mean > 120 then
        return nil, "RNG_ENTROPY_BAD"
    end
    return table.concat(out)
end

-- ========== Anti-debug / anti-tamper ==========

-- snapshot globals
local originalGlobals = {
    pairs = pairs,
    next = next,
    pcall = pcall,
    task_spawn = task and task.spawn,
    coroutine_wrap = coroutine and coroutine.wrap,
}

local function timingProbe()
    local loops = 3
    local total = 0
    for _ = 1, loops do
        local t0 = tick()
        local acc = 0
        for i = 1, 200000 do
            acc = acc + i
        end
        local dt = tick() - t0
        total = total + dt
    end
    local avg = total / loops
    return avg < 0.8, avg
end

local function checkPairsNext()
    local t = { a = 1, b = 2, c = 3, d = 4 }
    local pc, nc, px, nx = 0, 0, 0, 0

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

local function checkGlobalsType()
    local env = getfenv and getfenv() or _G

    local function check(name)
        local v = env[name]
        local tv = type(v)
        if tv == "nil" then
            return true
        end
        if tv == "string" or tv == "number" or tv == "boolean" then
            return false
        end
        return true
    end

    if not check("pairs") then return false, "GLOBAL_MUTATED" end
    if not check("next")  then return false, "GLOBAL_MUTATED" end
    if not check("pcall") then return false, "GLOBAL_MUTATED" end

    return true
end

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

local function checkMetatableLock()
    local t = {}
    setmetatable(t, { __metatable = "LOCKED" })
    local ok = pcall(setmetatable, t, {})
    return not ok
end

-- Anti HTTP spy: check request/http_request/syn.request/http.request có phải Lua wrapper
local debugLib = debug

local function detectHttpSpy()
    if not debugLib or type(debugLib.getinfo) ~= "function" then
        return true
    end

    local suspects = {}

    if request then
        table.insert(suspects, { name = "request", fn = request })
    end
    if http_request then
        table.insert(suspects, { name = "http_request", fn = http_request })
    end
    if syn and syn.request then
        table.insert(suspects, { name = "syn.request", fn = syn.request })
    end
    if http and http.request then
        table.insert(suspects, { name = "http.request", fn = http.request })
    end

    for _, s in ipairs(suspects) do
        local name, fn = s.name, s.fn
        if type(fn) == "function" then
            local ok, info = pcall(debugLib.getinfo, fn, "S")
            if ok and info and info.what == "Lua" then
                return false, "HTTP_SPY_WRAPPER(" .. name .. ")"
            end
        end
    end

    return true
end

local function snapshotGlobals()
    local env = getfenv and getfenv() or _G
    local snap = {}
    for k in pairs(env) do
        snap[k] = true
    end
    return snap
end

local function detectGlobalInject(before)
    local env = getfenv and getfenv() or _G
    for k in pairs(env) do
        if not before[k]
            and k ~= "SH_Service_Key"
            and k ~= "SH_Service_Token"
        then
            return false, k
        end
    end
    return true
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

    local snap = snapshotGlobals()
    task.spawn(function() local _ = 1 + 1 end)
    task.wait()
    local okInject, name = detectGlobalInject(snap)
    if not okInject then
        return false, "GLOBAL_INJECT_" .. tostring(name)
    end

    local okSpy, errSpy = detectHttpSpy()
    if not okSpy then
        return false, errSpy or "HTTP_SPY_DETECTED"
    end

    return true
end

-- ========== HTTP-layer encryption (blob) ==========

local function xorCrypt(str, key)
    local klen = #key
    local out = table.create(#str)
    for i = 1, #str do
        local c = string.byte(str, i)
        local k = string.byte(key, ((i - 1) % klen) + 1)
        out[i] = string.char(bxor(c, k))
    end
    return table.concat(out)
end

local function makeBlob(tbl)
    local json = Http:JSONEncode(tbl)
    local xored = xorCrypt(json, HTTP_LAYER_SECRET)
    local b64 = Http:Base64Encode(xored)
    return b64
end

-- ========== Base64url helpers (dùng HttpService) ==========

local function b64url_encode(raw)
    local std = Http:Base64Encode(raw)
    std = std:gsub("%+", "-"):gsub("/", "_"):gsub("=", "")
    return std
end

local function b64url_decode(data)
    data = data:gsub("-", "+"):gsub("_", "/")
    local padding = #data % 4
    if padding ~= 0 then
        data = data .. string.rep("=", 4 - padding)
    end
    local ok, decoded = pcall(function()
        return Http:Base64Decode(data)
    end)
    if not ok then
        return nil
    end
    return decoded
end

-- ========== SHA-1 / HMAC / HKDF (client-side token verify) ==========

local function leftrotate(x, n)
    return band(lshift(x, n), 0xFFFFFFFF) + rshift(x, 32 - n)
end

local function sha1(msg)
    local bytes = { msg:byte(1, #msg) }
    local original_len_in_bits = #bytes * 8

    -- append '1' bit
    table.insert(bytes, 0x80)

    -- pad with zeros until length % 64 == 56
    while (#bytes % 64) ~= 56 do
        table.insert(bytes, 0x00)
    end

    -- append length in bits (64 bits big‑endian)
    local high = math.floor(original_len_in_bits / 2^32)
    local low  = original_len_in_bits % 2^32
    local function append_word(w)
        table.insert(bytes, band(rshift(w, 24), 0xFF))
        table.insert(bytes, band(rshift(w, 16), 0xFF))
        table.insert(bytes, band(rshift(w, 8), 0xFF))
        table.insert(bytes, band(w, 0xFF))
    end
    append_word(high)
    append_word(low)

    local h0 = 0x67452301
    local h1 = 0xEFCDAB89
    local h2 = 0x98BADCFE
    local h3 = 0x10325476
    local h4 = 0xC3D2E1F0

    local w = {}

    for chunkStart = 1, #bytes, 64 do
        for i = 0, 15 do
            local idx = chunkStart + i * 4
            local b1 = bytes[idx]     or 0
            local b2 = bytes[idx + 1] or 0
            local b3 = bytes[idx + 2] or 0
            local b4 = bytes[idx + 3] or 0
            w[i] = band(((b1 * 0x1000000) + (b2 * 0x10000) + (b3 * 0x100) + b4), 0xFFFFFFFF)
        end
        for i = 16, 79 do
            local v = bxor(w[i - 3], w[i - 8], w[i - 14], w[i - 16])
            w[i] = band(leftrotate(v, 1), 0xFFFFFFFF)
        end

        local a, b, c, d, e = h0, h1, h2, h3, h4

        for i = 0, 79 do
            local f, k
            if i < 20 then
                f = bor(band(b, c), band(bnot(b), d))
                k = 0x5A827999
            elseif i < 40 then
                f = bxor(b, c, d)
                k = 0x6ED9EBA1
            elseif i < 60 then
                f = bor(band(b, c), band(b, d), band(c, d))
                k = 0x8F1BBCDC
            else
                f = bxor(b, c, d)
                k = 0xCA62C1D6
            end

            local temp = (leftrotate(a, 5) + f + e + k + w[i]) % 4294967296
            e = d
            d = c
            c = leftrotate(b, 30)
            b = a
            a = temp
        end

        h0 = (h0 + a) % 4294967296
        h1 = (h1 + b) % 4294967296
        h2 = (h2 + c) % 4294967296
        h3 = (h3 + d) % 4294967296
        h4 = (h4 + e) % 4294967296
    end

    local function wordToBytes(w)
        local b1 = band(rshift(w, 24), 0xFF)
        local b2 = band(rshift(w, 16), 0xFF)
        local b3 = band(rshift(w, 8), 0xFF)
        local b4 = band(w, 0xFF)
        return string.char(b1, b2, b3, b4)
    end

    return wordToBytes(h0)
        .. wordToBytes(h1)
        .. wordToBytes(h2)
        .. wordToBytes(h3)
        .. wordToBytes(h4)
end

local function hmac_sha1(key, msg)
    if #key > 64 then
        key = sha1(key)
    end
    if #key < 64 then
        key = key .. string.rep("\0", 64 - #key)
    end

    local o_key_pad = {}
    local i_key_pad = {}
    for i = 1, 64 do
        local kc = string.byte(key, i)
        o_key_pad[i] = string.char(bxor(kc, 0x5C))
        i_key_pad[i] = string.char(bxor(kc, 0x36))
    end

    o_key_pad = table.concat(o_key_pad)
    i_key_pad = table.concat(i_key_pad)

    local inner = sha1(i_key_pad .. msg)
    local final = sha1(o_key_pad .. inner)
    return final
end

local function hkdf_sha1(ikm, salt, info, length)
    local HASH_LEN = 20
    if #salt == 0 then
        salt = string.rep("\0", HASH_LEN)
    end
    local prk = hmac_sha1(salt, ikm)
    local okm = ""
    local t = ""
    local blocks = math.ceil(length / HASH_LEN)
    for i = 1, blocks do
        t = hmac_sha1(prk, t .. info .. string.char(i))
        okm = okm .. t
    end
    return string.sub(okm, 1, length)
end

local function secure_compare(a, b)
    if type(a) ~= "string" or type(b) ~= "string" then
        return false
    end
    local len_a = #a
    local len_b = #b
    local result = 0
    local max_len = math.max(len_a, len_b)
    for i = 1, max_len do
        local ca = string.byte(a, i) or 0
        local cb = string.byte(b, i) or 0
        result = bor(result, bxor(ca, cb))
    end
    return result == 0 and len_a == len_b
end

-- ========== Token parse & verify ==========

local function parseAndVerifyToken(token, key, hwid, nonce)
    if type(token) ~= "string" then
        return nil, "NO_TOKEN"
    end

    local p1, p2, p3 = token:match("([^%.]+)%.([^%.]+)%.([^%.]+)")
    if not p1 or not p2 or not p3 then
        return nil, "BAD_FORMAT"
    end

    local payloadRaw = b64url_decode(p1)
    local sig1Raw    = b64url_decode(p2)
    -- p3 là outer HMAC bằng SECRET_MAIN, client không biết => không verify

    if not payloadRaw or not sig1Raw then
        return nil, "B64_DECODE_FAIL"
    end

    local payload
    local ok, err = pcall(function()
        payload = Http:JSONDecode(payloadRaw)
    end)
    if not ok or type(payload) ~= "table" then
        return nil, "PAYLOAD_JSON_FAIL"
    end

    if payload.code ~= "AUTH_OK" then
        return nil, "PAYLOAD_BAD_CODE"
    end

    -- Verify hwidHash
    local hwidHashLocal = b64url_encode(sha1(hwid))
    if payload.hwidHash ~= hwidHashLocal then
        return nil, "HWID_HASH_MISMATCH"
    end

    -- Verify inner HMAC (HKDF + HMAC-SHA1)
    local clientKey = hkdf_sha1(
        key .. "|" .. hwid,
        sha1(key .. "|SALT"),
        nonce,
        20
    )

    local expectedSig1 = hmac_sha1(clientKey, payloadRaw)
    if not secure_compare(sig1Raw, expectedSig1) then
        return nil, "SIG1_MISMATCH"
    end

    return payload
end

-- ========== MAIN AUTH ==========

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

    local nonce, nErr = randomNonce(32)
    if not nonce then
        print("Auth Failed:", nErr or "NONCE_FAIL")
        return false
    end

    local hwid = getHWID()

    local blob = makeBlob({
        key = key,
        hwid = hwid,
        nonce = nonce,
    })

    local resp
    local okReq, errReq = pcall(function()
        resp = requestFunc({
            Url = API_BASE .. "/auth",
            Method = "POST",
            Headers = {
                ["Content-Type"] = "application/json"
            },
            Body = Http:JSONEncode({
                blob = blob
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

    if data.status ~= "AUTH_OK" then
        print("Auth Failed:", data.status)
        return false
    end

    local payload, perr = parseAndVerifyToken(data.token, key, hwid, nonce)
    if not payload then
        print("Auth Failed:", "TOKEN_FAIL_" .. tostring(perr))
        return false
    end

    -- Lưu token nếu bạn cần cho các request khác
    getgenv().SH_Service_Token = data.token

    print("Auth")
    return true, payload
end

return authSH
