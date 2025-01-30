local uci = luci.model.uci.cursor()
local fs = require "nixio.fs"
local sys = require "luci.sys"

m = Map("nginx-proxy", translate("SSL Configuration"),
    translate("Configure SSL/TLS settings for HTTPS support"))

-- SSL 主配置节
s = m:section(NamedSection, "ssl", "ssl", translate("SSL Settings"))

-- 启用SSL开关
enable = s:option(Flag, "enabled", translate("Enable SSL"),
    translate("Requires valid certificate and private key"))
enable.rmempty = false

-- 证书路径配置（支持ACME自动填充）
cert = s:option(Value, "cert_path", translate("Certificate Path"),
    translate("Path to SSL certificate file (PEM format)"))
cert:depends("enabled", "1")
cert.datatype = "file"
cert.default = "/etc/nginx/ssl/cert.pem"
function cert.validate(self, value)
    if not fs.access(value) then
        return nil, translate("Certificate file not found")
    end
    if fs.readfile(value):sub(1, 27) ~= "-----BEGIN CERTIFICATE-----" then
        return nil, translate("Invalid certificate format")
    end
    return value
end

-- 私钥路径配置
key = s:option(Value, "key_path", translate("Private Key Path"),
    translate("Path to private key file (PEM format)"))
key:depends("enabled", "1")
key.datatype = "file"
key.default = "/etc/nginx/ssl/key.pem"
function key.validate(self, value)
    if not fs.access(value) then
        return nil, translate("Private key file not found")
    end
    if fs.readfile(value):sub(1, 27) ~= "-----BEGIN PRIVATE KEY-----" and
       fs.readfile(value):sub(1, 32) ~= "-----BEGIN RSA PRIVATE KEY-----" then
        return nil, translate("Invalid private key format")
    end
    return value
end

-- 高级选项容器
adv = s:option(DummyValue, "adv_options", "")
adv.template = "nginx-proxy/ssl_adv_options"

-- 协议版本选择
protocols = s:option(ListValue, "protocols", translate("SSL Protocols"),
    translate("Recommended: TLSv1.2 TLSv1.3"))
protocols:depends("enabled", "1")
protocols:value("TLSv1.2 TLSv1.3", "TLS 1.2 + 1.3 (Modern)")
protocols:value("TLSv1.2", "TLS 1.2 Only")
protocols:value("TLSv1.3", "TLS 1.3 Only")
protocols.default = "TLSv1.2 TLSv1.3"

-- 加密套件配置
ciphers = s:option(Value, "ciphers", translate("Cipher Suites"),
    translate("Colon-separated cipher list"))
ciphers:depends("enabled", "1")
ciphers.default = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
function ciphers.validate(self, value)
    if not value:match("^[A-Za-z0-9%-_]+(:[A-Za-z0-9%-_]+)+$") then
        return nil, translate("Invalid cipher format")
    end
    return value
end

-- HSTS配置
hsts = s:option(Flag, "hsts", translate("Enable HSTS"),
    translate("HTTP Strict Transport Security"))
hsts:depends("enabled", "1")

hsts_age = s:option(Value, "hsts_age", translate("HSTS Max Age"),
    translate("Recommended >= 63072000 (2 years)"))
hsts_age.datatype = "uinteger"
hsts_age.default = "63072000"
hsts_age:depends("hsts", "1")

hsts_include_sub = s:option(Flag, "hsts_include_sub", translate("Include Subdomains"))
hsts_include_sub.default = "1"
hsts_include_sub:depends("hsts", "1")

-- OCSP装订
ocsp = s:option(Flag, "ocsp", translate("OCSP Stapling"),
    translate("Enable Online Certificate Status Protocol stapling"))
ocsp:depends("enabled", "1")

-- 会话缓存
session_cache = s:option(ListValue, "session_cache", translate("Session Cache"))
session_cache:value("none", translate("Disable"))
session_cache:value("builtin", "Built-in")
session_cache:value("shared:SSL:10m", "Shared (10MB)")
session_cache.default = "shared:SSL:10m"
session_cache:depends("enabled", "1")

-- 智能证书检查
function m.on_parse(self)
    if enable:formvalue("ssl") == "1" then
        -- 自动检测ACME证书更新
        local acme_enabled = uci:get("nginx-proxy", "acme", "enabled") or "0"
        if acme_enabled == "1" then
            local domain = uci:get("nginx-proxy", "proxy", "domain")
            local cert_path = "/etc/ssl/acme/"..domain.."_fullchain.cer"
            if fs.access(cert_path) then
                uci:set("nginx-proxy", "ssl", "cert_path", cert_path)
                uci:set("nginx-proxy", "ssl", "key_path", "/etc/ssl/acme/"..domain..".key")
            end
        end
        
        -- 验证证书私钥匹配
        local cert = cert:formvalue("ssl") or ""
        local key = key:formvalue("ssl") or ""
        if cert ~= "" and key ~= "" then
            local cert_md5 = sys.exec("openssl x509 -noout -modulus -in "..cert.." | openssl md5")
            local key_md5 = sys.exec("openssl rsa -noout -modulus -in "..key.." | openssl md5")
            if cert_md5 ~= key_md5 then
                m.message = translate("Certificate and private key do not match!")
            end
        end
    end
end

-- 配置应用后操作
function m.on_commit(self)
    if enable:formvalue("ssl") == "1" then
        -- 创建SSL目录
        if not fs.access("/etc/nginx/ssl") then
            fs.mkdir("/etc/nginx/ssl")
            fs.chmod("/etc/nginx/ssl", 700)
        end
        
        -- 触发配置重新生成
        sys.call("/usr/libexec/nginx-proxy/generate-config >/dev/null 2>&1")
    end
end

return m
