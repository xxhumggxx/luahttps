local _S = game:GetService("HttpService")
local _A = game:GetService("RbxAnalyticsService")

local __API = "http://217.154.114.227:9971/api"
local __AUD = "SH_Project"
local __ISS = "SH_Service"

local __rq = request or http_request or (http and http.request) or (syn and syn.request)
if not __rq then error("SH_Service: HTTP request missing") end

local __bit = bit32 or bit
if not __bit then error("SH_Service: bit lib missing") end
local band, bor, bxor, rshift, lshift = __bit.band, __bit.bor, __bit.bxor, __bit.rshift, __bit.lshift
local bnot = __bit.bnot or function(a) return bxor(a, 0xFFFFFFFF) end

local function rr(x,n)
    n=n%32
    return bor(rshift(x,n), lshift(band(x,0xFFFFFFFF), 32-n))
end

local function _junk()
    local t = 0
    for i=1,2 do t = bxor(t, i*7) end
    return t
end
local __J = _junk()

local function _hw()
    local ok, id = pcall(function() return _A:GetClientId() end)
    if ok and type(id)=="string" and #id>=10 then
        id = id:gsub("[^a-zA-Z0-9_%-]","")
        if #id>=10 and #id<=128 then return id end
    end
    return "FALLBACK_"..tostring(math.random(100000,999999))
end

local B64="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local function b64e(data)
    local r={}
    for i=1,#data,3 do
        local b1=string.byte(data,i)
        local b2=string.byte(data,i+1)
        local b3=string.byte(data,i+2)
        local n=lshift(b1,16)+lshift(b2 or 0,8)+(b3 or 0)
        local c1=rshift(band(n,0xFC0000),18)+1
        local c2=rshift(band(n,0x03F000),12)+1
        local c3=rshift(band(n,0x000FC0),6)+1
        local c4=band(n,0x00003F)+1
        r[#r+1]=B64:sub(c1,c1)
        r[#r+1]=B64:sub(c2,c2)
        r[#r+1]=b2 and B64:sub(c3,c3) or "="
        r[#r+1]=b3 and B64:sub(c4,c4) or "="
    end
    return table.concat(r)
end
local function b64d(data)
    data=data:gsub("[^"..B64.."=]","")
    local r={}
    for i=1,#data,4 do
        local c1=string.find(B64,data:sub(i,i)) or 1
        local c2=string.find(B64,data:sub(i+1,i+1)) or 1
        local c3=string.find(B64,data:sub(i+2,i+2)) or 1
        local c4=string.find(B64,data:sub(i+3,i+3)) or 1
        c1,c2,c3,c4=c1-1,c2-1,c3-1,c4-1
        local n=lshift(c1,18)+lshift(c2,12)+lshift(c3,6)+c4
        local b1=band(rshift(n,16),0xFF)
        local b2=band(rshift(n,8),0xFF)
        local b3=band(n,0xFF)
        r[#r+1]=string.char(b1)
        if data:sub(i+2,i+2)~="=" then r[#r+1]=string.char(b2) end
        if data:sub(i+3,i+3)~="=" then r[#r+1]=string.char(b3) end
    end
    return table.concat(r)
end
local function b64u_enc(raw) return b64e(raw):gsub("%+","-"):gsub("/","_"):gsub("=+$","") end
local function b64u_dec(s)
    s=s:gsub("-","+"):gsub("_","/")
    local p=#s%4
    if p>0 then s=s..string.rep("=",4-p) end
    return b64d(s)
end

local sha256_k = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
}

local function sha256(msg)
    local bytes = { msg:byte(1, #msg) }
    local original_len_in_bits = #bytes * 8
    table.insert(bytes, 0x80)
    while (#bytes % 64) ~= 56 do
        table.insert(bytes, 0x00)
    end
    for i = 7, 0, -1 do
        table.insert(bytes, band(rshift(original_len_in_bits, i * 8), 0xFF))
    end

    local h0 = 0x6a09e667
    local h1 = 0xbb67ae85
    local h2 = 0x3c6ef372
    local h3 = 0xa54ff53a
    local h4 = 0x510e527f
    local h5 = 0x9b05688c
    local h6 = 0x1f83d9ab
    local h7 = 0x5be0cd19

    local w = {}

    for chunkStart = 1, #bytes, 64 do
        for i = 0, 15 do
            local idx = chunkStart + i * 4
            local b1 = bytes[idx] or 0
            local b2 = bytes[idx + 1] or 0
            local b3 = bytes[idx + 2] or 0
            local b4 = bytes[idx + 3] or 0
            w[i] = band(((b1 * 0x1000000) + (b2 * 0x10000) + (b3 * 0x100) + b4), 0xFFFFFFFF)
        end

        for i = 16, 63 do
            local s0 = bxor(rrotate32(w[i - 15], 7), rrotate32(w[i - 15], 18), rshift(w[i - 15], 3))
            local s1 = bxor(rrotate32(w[i - 2], 17), rrotate32(w[i - 2], 19), rshift(w[i - 2], 10))
            w[i] = band((w[i - 16] + s0 + w[i - 7] + s1), 0xFFFFFFFF)
        end

        local a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

        for i = 0, 63 do
            local S1 = bxor(rrotate32(e, 6), rrotate32(e, 11), rrotate32(e, 25))
            local ch = bxor(band(e, f), band(bnot(e), g))
            local temp1 = (h + S1 + ch + sha256_k[i + 1] + w[i]) % 4294967296
            local S0 = bxor(rrotate32(a, 2), rrotate32(a, 13), rrotate32(a, 22))
            local maj = bxor(band(a, b), band(a, c), band(b, c))
            local temp2 = (S0 + maj) % 4294967296

            h = g
            g = f
            f = e
            e = (d + temp1) % 4294967296
            d = c
            c = b
            b = a
            a = (temp1 + temp2) % 4294967296
        end

        h0 = (h0 + a) % 4294967296
        h1 = (h1 + b) % 4294967296
        h2 = (h2 + c) % 4294967296
        h3 = (h3 + d) % 4294967296
        h4 = (h4 + e) % 4294967296
        h5 = (h5 + f) % 4294967296
        h6 = (h6 + g) % 4294967296
        h7 = (h7 + h) % 4294967296
    end

    local function wordToBytes(wv)
        local b1 = band(rshift(wv, 24), 0xFF)
        local b2 = band(rshift(wv, 16), 0xFF)
        local b3 = band(rshift(wv, 8), 0xFF)
        local b4 = band(wv, 0xFF)
        return string.char(b1, b2, b3, b4)
    end

    return wordToBytes(h0)
        .. wordToBytes(h1)
        .. wordToBytes(h2)
        .. wordToBytes(h3)
        .. wordToBytes(h4)
        .. wordToBytes(h5)
        .. wordToBytes(h6)
        .. wordToBytes(h7)
end

local function hmac_sha256(key, msg)
    if #key > 64 then
        key = sha256(key)
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

    local inner = sha256(i_key_pad .. msg)
    local final = sha256(o_key_pad .. inner)
    return final
end

local function hkdf_sha256(ikm, salt, info, length)
    local HASH_LEN = 32
    if #salt == 0 then
        salt = string.rep("\0", HASH_LEN)
    end
    local prk = hmac_sha256(salt, ikm)
    local okm = ""
    local t = ""
    local blocks = math.ceil(length / HASH_LEN)
    for i = 1, blocks do
        t = hmac_sha256(prk, t .. info .. string.char(i))
        okm = okm .. t
    end
    return string.sub(okm, 1, length)
end

local dbg=debug
local function _spy()
    if not dbg or type(dbg.getinfo)~="function" then return true end
    local L={}
    if request then L[#L+1]=request end
    if http_request then L[#L+1]=http_request end
    if syn and syn.request then L[#L+1]=syn.request end
    if http and http.request then L[#L+1]=http.request end
    for _,fn in ipairs(L) do
        local ok,info=pcall(dbg.getinfo,fn,"S")
        if ok and info and info.what=="Lua" then
            return false,"HTTP_SPY_WRAPPER"
        end
    end
    return true
end

local function _parse(token, hwidHash)
    local p1,p2,p3=token:match("([^%.]+)%.([^%.]+)%.([^%.]+)")
    if not p1 or not p2 or not p3 then return nil,"BAD_FORMAT" end
    local payloadRaw=b64u_dec(p1)
    local payload=_S:JSONDecode(payloadRaw)
    if type(payload)~="table" then return nil,"BAD_PAYLOAD" end
    if payload.code~="SH_Service_OK" then return nil,"BAD_CODE" end
    if payload.hwidHash~=hwidHash then return nil,"HWID_HASH_MISMATCH" end
    if payload.iss~=__ISS then return nil,"ISS_MISMATCH" end
    if payload.aud~=__AUD then return nil,"AUD_MISMATCH" end
    if payload.exp and os.time()>payload.exp then return nil,"TOKEN_EXPIRED" end
    return payload
end

local function authSH()
    local t0=tick()
    print([==[
SH_Service Auth SDK v2
__  __ ____ 
\ \/ /|  _ \
 \  / | | | |
 /  \ | |_| |
/_/\_\|____/
]==])

    local key=getgenv().SH_Service_Key
    if type(key)~="string" or not key:match("^[A-F0-9]+$") or #key~=32 then
        print("Auth Failed: KEY_FORMAT_INVALID") return false
    end

    local okSpy,why=_spy()
    if not okSpy then print("Auth Failed:",why) return false end

    local hwid=_hw()
    local hwidHash=b64u_enc(sha256(hwid))

    local chResp=__rq({
        Url=__API.."/challenge",
        Method="POST",
        Headers={["Content-Type"]="application/json"},
        Body=_S:JSONEncode({hwidHash=hwidHash})
    })
    if not chResp or chResp.StatusCode~=200 then
        print("Auth Failed: CHALLENGE_HTTP_FAIL") return false
    end

    local ch=_S:JSONDecode(chResp.Body)
    if type(ch)~="table" or ch.status~="OK" then
        print("Auth Failed:", ch.status or "CHALLENGE_BAD") return false
    end

    local session=ch.session
    local nonce_s=b64u_dec(ch.nonce_s)
    local salt=b64u_dec(ch.salt)
    local expMs=(ch.exp or 0)*1000

    local cnRaw=_S:GenerateGUID(false).."|"..tostring(os.clock()).."|"..tostring(tick())
    local clientNonce=b64u_enc(sha256(cnRaw))

    local ikm=key.."|"..hwidHash.."|"..clientNonce.."|"..nonce_s
    local clientKey=hkdf_sha256(ikm, salt, "AUTHv2", 32)

    local proofMsg=session.."|"..tostring(expMs).."|"..hwidHash
    local proof=b64u_enc(hmac_sha256(clientKey, proofMsg))

    local vResp=__rq({
        Url=__API.."/verify",
        Method="POST",
        Headers={["Content-Type"]="application/json"},
        Body=_S:JSONEncode({
            session=session,
            hwidHash=hwidHash,
            clientNonce=clientNonce,
            proof=proof,
            key=key
        })
    })
    if not vResp or vResp.StatusCode~=200 then
        print("Auth Failed: VERIFY_HTTP_FAIL") return false
    end

    local dat=_S:JSONDecode(vResp.Body)
    if type(dat)~="table" or dat.status~="AUTH_OK" or type(dat.token)~="string" then
        print("Auth Failed:", dat.status or "VERIFY_BAD") return false
    end

    local payload,perr=_parse(dat.token, hwidHash)
    if not payload then
        print("Auth Failed: TOKEN_FAIL_"..tostring(perr)) return false
    end

    getgenv().SH_Service_Token=dat.token
    print("SH_Service:Authenticated")
    print("SH_Service: time:"..(tick()-t0).." s")

    local gNonce=b64u_enc(sha256(_S:GenerateGUID(false)..tostring(tick())))
    local gSign=b64u_enc(hmac_sha256(
        key,
        b64u_enc(dat.token).."."..b64u_enc(gNonce)
    ))

    local gResp=__rq({
        Url=__API.."/group",
        Method="POST",
        Headers={["Content-Type"]="application/json"},
        Body=_S:JSONEncode({accesstoken=dat.token, nonce=gNonce, sign=gSign})
    })
    if gResp and gResp.StatusCode==200 then
        local gd=_S:JSONDecode(gResp.Body)
        if gd and gd.status=="OK" then
            getgenv().SH_UserGroup=gd.data
            getgenv().SH_AuthId=gd.authid
        end
    end

    return true, payload
end

return authSH
