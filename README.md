## SecureDrop NG in OpenResty
Quick toy implementation of the SecureDrop server described in the [SecureDrop POC](https://github.com/freedomofpress/securedrop-poc) repository. It depends only on `cjson` and `luasodium`. It is quite fast, but does not support attachments and does lack mitigations (decoy messages, time). It is intended to show how portable is a server implementation and do some more realistic benchmark of how much it can scale.

## Usage
 - Install `luasodium` using LuaRocks
 - Copy the module in a Lua path or edit the nginx config to load it
 - Use the reference nginx config in this repo
 - Generate the required keys using SecureDrop POC `pki.py`
 - Load the root (FPF) and intermediate (Newsroom) key using `deploy_keys.py`
 - Test using the `demo.sh` script in the other repo (remember to change commons.SERVER)
