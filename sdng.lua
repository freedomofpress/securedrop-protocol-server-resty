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

-- Base64 Decoder Helper
local function b64decode(input)
    local ok, output = pcall(luasodium.sodium_base642bin, input, 1)

    if ok and output then
        return output
    end
    
    http_exit({status="KO"}, ngx.HTTP_BAD_REQUEST)
    return
end

-- Base64 Encoder Helper
local function b64encode(input)
    local ok, output = pcall(luasodium.sodium_bin2base64, input, 1)

    if ok and output then
        return output
    end

    http_exit({status="KO"}, ngx.HTTP_INTERNAL_SERVER_ERROR)
    return
end

-- Hex Encoder Helper
local function hexencode(input)
    local ok, output = pcall(luasodium.sodium_bin2hex, input)

    if ok and output then
        return output
    end

    http_exit({status="KO"}, ngx.HTTP_INTERNAL_SERVER_ERROR)
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
        http_exit({status="KO"}, ngx.HTTP_FORBIDDEN)
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
    local success = luasodium.crypto_sign_verify_detached(nr_sig, nr_key, fpf_key)
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
end

-- POST method on /journalists
local function add_journalists()
    local json = get_json_body()
    
    -- Check that all JSON keys are there
    check_json_keys(json, {"journalist_key", "journalist_sig",
                           "journalist_fetching_key", "journalist_fetching_sig"})

    -- Decode the base64
    local j_key = b64decode(json["journalist_key"])
    local j_sig = b64decode(json["journalist_sig"])
    local jf_key = b64decode(json["journalist_fetching_key"])
    local jf_sig = b64decode(json["journalist_fetching_sig"])

    local red = init_redis()
    local fpf_key, nr_key, nr_sig = keys_from_redis(red)

    nr_key = b64decode(nr_key)
    local success_j = luasodium.crypto_sign_verify_detached(j_sig, j_key, nr_key)
    local success_jf = luasodium.crypto_sign_verify_detached(jf_sig, jf_key, j_key)

    if not success_jf or not success_jf then
        http_exit({status="KO"}, ngx.HTTP_UNAUTHORIZED)
        return
    end

    -- Ed25519 keys are so short that hashing the pubkey does not save anything
    -- journalist_uid = b64encode(luasodium.crypto_generichash(j_key))

    red:sadd("journalists", json_encode({
                                            journalist_key=b64encode(j_key),
                                            journalist_sig=b64encode(j_sig),
                                            journalist_fetching_key=b64encode(jf_key),
                                            journalist_fetching_sig=b64encode(jf_sig)
                                        }))
    http_exit({status="OK"}, ngx.HTTP_OK)
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
    local message_id = hexencode(message_id)
    red:set("message:"..message_id, json_encode({message_ciphertext=json["message_ciphertext"],
                                                 message_public_key=json["message_public_key"],
                                                 message_gdh=json["message_gdh"]}))

    http_exit({status="OK"}, ngx.HTTP_OK)
end

-- GET method on /message/<message_id>
local function get_message()
    message_id = string.sub(ngx.var.uri, 10, 73)
    if #message_id ~= 64 then
        http_exit({status="KO"}, ngx.HTTP_BAD_REQUEST)
    end

    red = init_redis()
    message = red:get("message:"..message_id)
    message = json_decode(message)

    http_exit({status="OK",
               message={
                message_public_key=message["message_public_key"],
                message_ciphertext=message["message_ciphertext"]
               }
              }, ngx.HTTP_OK)
    return    

end

-- POST method on /ephemeral_keys
local function add_ephemeral_keys()
    local json = get_json_body()
    local j_key

    -- Check that all JSON keys are there
    check_json_keys(json, {"journalist_key", "ephemeral_keys"})
    local red = init_redis()
    local journalists = red:smembers("journalists")

    -- Verify that the journalist exists in the database and get
    -- the proper public key for verifiation
    for _, journalist in ipairs(journalists) do
        local journalist_from_db = json_decode(journalist)
        if journalist_from_db["journalist_key"] == json["journalist_key"] then
            j_key = b64decode(journalist_from_db["journalist_key"])
            break
        end
    end
    
    -- If the journalist exists
    if j_key then
        local counter = 0
        -- For every ephemeral key to add, verify its signsature
        for _, ephemeral_key in ipairs(json["ephemeral_keys"]) do
            local je_sig = b64decode(ephemeral_key["ephemeral_sig"])
            local je_key = b64decode(ephemeral_key["ephemeral_key"])
            local success_je = luasodium.crypto_sign_verify_detached(je_sig, je_key, j_key)
            if success_je then
                -- If the ephemeral key is correctly signed, add it to the redis set
                red:sadd("journalist:"..hexencode(j_key), json_encode({ephemeral_key=b64encode(je_key),
                                                                       ephemeral_sig=b64encode(je_sig)}))
                counter = counter + 1
            end
        end
        http_exit({status="OK",count=counter}, ngx.HTTP_OK)
    else
        http_exit({status="KO"}, ngx.HTTP_UNAUTHORIZED)
    end
end

-- GET method on /ephemeral_keys
function get_ephemeral_keys()
    local red = init_redis()

    local journalists = red:smembers("journalists")

    local ephemeral_keys = {}
    for _, journalist in ipairs(journalists) do
        local j_key = b64decode(json_decode(journalist)["journalist_key"])
        local ephemeral_key = red:spop("journalist:"..hexencode(j_key))
        ephemeral_key = json_decode(ephemeral_key)
        ephemeral_key["journalist_key"] = b64encode(j_key)
        table.insert(ephemeral_keys, ephemeral_key)
    end
    http_exit({status="OK",
               count=#ephemeral_keys,
               ephemeral_keys=ephemeral_keys
              }, ngx.HTTP_OK)
    return
end

-- GET method on /fetch
function get_fetch()
    local red = init_redis()

    local potential_messages = {}

    -- Get the redis keys for all the messages
    local message_keys = red:keys("message:*")
    for _, message_key in ipairs(message_keys) do
        -- Isolate the message_id
        local message_id = string.sub(message_key, 9)
        -- Get the actual message JSON fields
        local message = red:get(message_key)
        message = json_decode(message)

        -- Generate the per message server keypair RE, keep just the privkey
        local _, request_ephemeral_privkey = luasodium.crypto_box_keypair()
        local message_gdh = b64decode(message["message_gdh"])
        local message_public_key = b64decode(message["message_public_key"])
        local message_server_gdh = luasodium.crypto_scalarmult(request_ephemeral_privkey, message_public_key)

        -- TODO crypto box also signs the encrypted envelope, which has no purpose here
        -- and it is just cpu and space overhead
        local nonce = luasodium.randombytes_buf(24)
        -- Useful debugging line to check if the shared key match
        --local key = luasodium.crypto_box_beforenm(message_gdh, request_ephemeral_privkey)
        local encrypted_message_id = luasodium.crypto_box_easy(message_id, nonce, message_gdh, request_ephemeral_privkey)
        -- This took a lot of debugging: pynacl is higher level
        -- and transparently construct the ciphertext with the random nonce and appends it
        -- in luasodium that has to happen manually
        encrypted_message_id = nonce..encrypted_message_id

        table.insert(potential_messages, {enc=b64encode(encrypted_message_id),
                                          gdh=b64encode(message_server_gdh),
                                        })
    end

    -- TODO add decoy messages

    -- TODO add random sleep to prevent timing attacks on the number of messages

    http_exit({status="OK", count=#potential_messages, messages=potential_messages}, ngx.HTTP_OK)
end


-- request handler /
function _M.index()
    if ngx.req.get_method() == "GET" then
        http_exit({status="OK"}, ngx.HTTP_OK)
    else
        http_exit({status="KO"}, ngx.HTTP_NOT_ALLOWED)
    end
    return
end

-- request handler /keys
function _M.keys()
    -- Quick way to initialize this instance
    -- Can be done only once, requires to upload the FPF key,
    -- the Newsroom key and its signature
    if ngx.req.get_method() == "POST" then
        add_keys()
    elseif ngx.req.get_method() == "GET" then
        get_keys()
    else
        http_exit({status="KO"}, ngx.HTTP_NOT_ALLOWED)
    end
    return
end

-- request handler /journalists
function _M.journalists()
    if ngx.req.get_method() == "POST" then
        add_journalists()
    elseif ngx.req.get_method() == "GET" then
        get_journalists()
    else
        http_exit({status="KO"}, ngx.HTTP_NOT_ALLOWED)
    end
    return
end

-- request handler /message
function _M.message()
    local red = init_redis()
    
    if ngx.req.get_method() == "POST" then
        add_message()
    elseif ngx.req.get_method() == "GET" then
        get_message()
    else
        http_exit({status="KO"}, ngx.HTTP_NOT_ALLOWED)
    end
    return
end

function _M.fetch()
    if ngx.req.get_method() == "GET" then
        get_fetch()
    else
        http_exit({status="KO"}, ngx.HTTP_NOT_ALLOWED)
        return
    end
end

function _M.ephemeral_keys()    
    if ngx.req.get_method() == "POST" then
        add_ephemeral_keys()
    elseif ngx.req.get_method() == "GET" then
        get_ephemeral_keys()
    else
        http_exit({status="KO"}, ngx.HTTP_NOT_ALLOWED)
    end
    return
end

return _M