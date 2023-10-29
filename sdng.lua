local cjson = require("cjson")
local json_encode = cjson.encode
local json_decode = cjson.decode

local luasodium = require("luasodium")

local redis = require("resty.redis")

local _M = {
    _DESCRIPTION = "Next-Generation SecureDrop server",
    _VERSION = '0.1',
}

-- HTTP Response Helper
local function http_exit(json, status_code)
    ngx.status = status_code
    ngx.say(json_encode(json))
    ngx.exit(status_code)
end

-- JSON Body Helper
local function get_json_body()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local ok, json = pcall(json_decode, body)

    if ok and json then
        return json
    end

    http_exit({status="KO"}, ngx.HTTP_BAD_REQUEST)
    return
end

local function check_json_keys(json, keys)
    for _, key in ipairs(keys) do
        if not json[key] then
            http_exit({status="KO"}, ngx.HTTP_BAD_REQUEST)
        end
    end
end

-- Base64 Helper
local function b64decode(input)
    local ok, output = pcall(luasodium.sodium_base642bin, input, 1)

    if ok and output then
        return output
    end
    
    http_exit({status="KO"}, ngx.HTTP_BAD_REQUEST)
    return
end

-- Redis Helper
local function init_redis()
    local red = redis:new()
    local ok, err = red:connect("127.0.0.1", 6379)

    return red
end

local function keys_from_redis(red)
    local fpf_key, err = red:get("fpf_key")
    local nr_key, err = red:get("newsroom_key")
    local nr_sig, err = red:get("newsroom_sig")
    return fpf_key, nr_key, nr_sig
end

-- POST method on /keys
local function add_keys()
    local red = init_redis()
    local fpf_key, nr_key, nr_sig = keys_from_redis(red)

    if fpf_key ~= ngx.null then
        -- Instance has already been initialized
        http_error_and_exit(ngx.HTTP_FORBIDDEN)
        return
    end

    local json = get_json_body()

    -- Check that all JSON keys are there
    check_json_keys(json, {"fpf_key", "newsroom_key", "newsroom_sig"})

    -- Decode the base64
    fpf_key = b64decode(json["fpf_key"])
    nr_key = b64decode(json["newsroom_key"])
    nr_sig = b64decode(json["newsroom_sig"])

    -- Start verifying the signatures
    --local success = luasodium.crypto_sign_verify_detached(nr_sig, nr_key, fpf_key)
    if success then
        red:set("fpf_key", json["fpf_key"])
        red:set("newsroom_key", json["newsroom_key"])
        red:set("newsroom_sig", json["newsroom_sig"])

        http_exit({status="OK"}, ngx.HTTP_OK)
    else
        http_exit({status="KO"}, ngx.HTTP_BAD_REQUEST)
    end

    return
end

-- GET method on /keys
local function get_keys()
    local red = init_redis()
    local fpf_key, nr_key, nr_sig = keys_from_redis(red)

    -- Check if the instance is initialized
    if fpf_key == ngx.null then
        http_exit({status="KO"}, ngx.HTTP_SERVICE_UNAVAILABLE)
        return
    end

    -- Serve the keys
    http_exit({fpf_key=fpf_key,
               newrsoom_key=nr_key,
               newsroom_sig=nr_sig
            }, ngx.HTTP_OK)
    return
end

-- GET method on /journalists
local function get_journalists()
    local red = init_redis()

    -- Fetch all from the journalists redis set
    local journalists = red:smembers("journalists")

    local journalists_list = {}
    for _, journalist_json in ipairs(journalists) do
        -- Decoding fo re-encoding is not smart, but avoids doing manual json
        table.insert(journalists_list, json_decode(journalist_json))
    end

    -- Serve the list in the expected format
    http_exit({status="OK",
               count=#journalists_list,
               journalists=journalists_list
              }, ngx.HTTP_OK)
    return
end

-- POST method on /journalists
local function add_journalists()
    local json = get_json_body()
    
    -- Check that all JSON keys are there
    check_json_keys(json, {"journalist_key", "journalist_sig",
                           "journalist_fetching_key", "journalist_fetching_sig"})

    -- Decode the base64
    -- TODO handle decode errors
    local j_key = b64decode(json["journalist_key"])
    local j_sig = b64decode(json["journalist_sig"])
    local jf_key = b64decode(json["journalist_fetching_key"])
    local jf_sig = b64decode(json["journalist_fetching_sig"])

    local red = init_redis()
    local fpf_key, nr_key, nr_sig = keys_from_redis(red)

    nr_key = b64decode(nr_key)
    local success_j = luasodium.crypto_sign_verify_detached(j_sig, j_key, nr_key)
    local success_jf = luasodium.crypto_sign_verify_detached(jf_sig, jf_key, j_key)

    if not success_j or not success_jf then
        http_exit({status="KO"}, ngx.HTTP_UNAUTHORIZED)
        return
    end

    -- TODO re-encode and insert
    -- redis:sadd()
    http_exit({status="OK"}, ngx.HTTP_OK)
    return
end

-- POST method on /message
local function add_message()
    local json = get_json_body()
    
    -- Check that all JSON keys are there
    check_json_keys(json, {"message_ciphertext", "message_public_key", "message_gdh"})


    local red = init_redis()
    -- Re-econding here is a precaution to drop unwanted keys and
    -- build sane JSON
    local message_id = luasodium.randombytes_buf(32)
    message_id = luasodium.sodium_bin2hex(message_id)
    red:set("message:"..message_id, json_encode({message_ciphertext=json["message_ciphertext"],
                                                 message_public_key=json["message_public_key"],
                                                 message_gdh=json["message_gdh"]}))

    http_exit({status="OK"}, ngx.HTTP_OK)
end

-- request handler /
function _M.index()
    if ngx.req.get_method() == "GET" then
        http_exit({status="OK"}, ngx.HTTP_OK)
    else
        http_exit({status="KO"}, ngx.HTTP_NOT_ALLOWED)
        return
    end
end

-- request handler /keys
function _M.keys()
    -- Quick way to initialize this instance
    -- Can be done only once, requires to upload the FPF key,
    -- the Newsroom key and its signature
    if ngx.req.get_method() == "POST" then
        add_keys()
        return
    elseif ngx.req.get_method() == "GET" then
        get_keys()
        return
    else
        http_exit({status="KO"}, ngx.HTTP_NOT_ALLOWED)
        return
    end
end

-- request handler /journalists
function _M.journalists()
    if ngx.req.get_method() == "POST" then
        add_journalists()
        return
    elseif ngx.req.get_method() == "GET" then
        get_journalists()
        return
    else
        http_exit({status="KO"}, ngx.HTTP_NOT_ALLOWED)
        return
    end
end

-- request handler /message
function _M.message()
    local red = init_redis()
    
    if ngx.req.get_method() == "POST" then
        add_message()
    else
        http_exit({status="KO"}, ngx.HTTP_NOT_ALLOWED)
        return
    end
end

function _M.fetch()
    if ngx.req.get_method() == "GET" then
        return
    else
        return
    end
end

function _M.ephemeral_keys()    
    if ngx.req.get_method() == "POST" then
        return
    elseif ngx.req.get_method() == "GET" then
        return
    else
        return
    end
end

return _M