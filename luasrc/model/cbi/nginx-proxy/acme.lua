local uci = luci.model.uci.cursor()
local fs = require "nixio.fs"
local sys = require "luci.sys"
local http = require "luci.http"

m = Map("nginx-proxy", translate("ACME Automation"),
    translate("Automated Certificate Management using ACME protocol (Let's Encrypt)"))

-- 主配置节
s = m:section(NamedSection, "acme", "acme", translate("ACME Settings"))

-- 启用ACME
enable = s:option(Flag, "enabled", translate("Enable ACME"),
    translate("Automatically obtain and renew SSL certificates"))
enable.rmempty = false

-- 注册邮箱
email = s:option(Value, "email", translate("Account Email"),
    translate("Important for certificate recovery and expiry notices"))
email.datatype = "email"
email:depends("enabled", "1")

-- 证书域名列表
domains = s:option(DynamicList, "domains", translate("Certificate Domains"),
    translate("Separate multiple domains with spaces, supports wildcards (*.example.com)"))
domains:depends("enabled", "1")
function domains.validate(self, value)
    for _, domain in ipairs(value) do
        if not domain:match("^%*?%.?[a-zA-Z0-9-]+%.[a-zA-Z]{2,}$") then
            return nil, translatef("Invalid domain format: %s", domain)
        end
    end
    return value
end

-- ACME服务器选择
server = s:option(ListValue, "server", translate("ACME Server"))
server:depends("enabled", "1")
server:value("https://acme-v02.api.letsencrypt.org/directory", translate("Let's Encrypt Production"))
server:value("https://acme-staging-v02.api.letsencrypt.org/directory", translate("Let's Encrypt Staging"))
server.default = "https://acme-v02.api.letsencrypt.org/directory"

-- 验证方式
validation = s:option(ListValue, "validation", translate("Validation Method"))
validation:depends("enabled", "1")
validation:value("http", "HTTP-01 (Webroot)")
validation:value("dns", "DNS-01 (DNS TXT Record)")
validation.default = "http"

-- Webroot路径
webroot = s:option(Value, "webroot", translate("Webroot Path"),
    translate("Where to place ACME challenge files"))
webroot:depends("validation", "http")
webroot.default = "/var/www/acme"
webroot.datatype = "directory"

-- DNS提供商选择
dns_provider = s:option(ListValue, "dns_provider", translate("DNS Provider"))
dns_provider:depends("validation", "dns")
dns_provider:value("cloudflare", "Cloudflare")
dns_provider:value("aliyun", "Aliyun DNS")
dns_provider:value("digitalocean", "DigitalOcean")
dns_provider:value("custom", "Custom API")

-- DNS API配置
api_key = s:option(Value, "api_key", translate("API Key"),
    translate("Provider-specific API credentials"))
api_key:depends("dns_provider", "cloudflare")
api_key:depends("dns_provider", "aliyun")
api_key:depends("dns_provider", "digitalocean")
api_key.password = true

custom_api = s:option(Value, "custom_api", translate("Custom API Script"),
    translate("Path to custom DNS API script"))
custom_api:depends("dns_provider", "custom")
custom_api.datatype = "file"

-- 证书状态显示
cert_status = s:option(DummyValue, "_status", translate("Certificate Status"))
cert_status.template = "nginx-proxy/acme_status"
cert_status:depends("enabled", "1")

-- 操作按钮
action = s:option(Button, "_action", translate("Actions"))
action.template = "nginx-proxy/acme_actions"

-- 立即申请证书
function action.write(self, section, value)
    local cmd = build_acme_cmd()
    local success = sys.call(cmd .. " --issue")
    
    if success == 0 then
        update_cert_paths()
        m.message = translate("Certificate successfully issued")
    else
        m.message = translate("Certificate issuance failed")
    end
end

-- 构建ACME命令
function build_acme_cmd()
    local cmd = "acme.sh --force "
    cmd = cmd .. "--server " .. uci:get("nginx-proxy", "acme", "server") .. " "
    cmd = cmd .. "--email " .. uci:get("nginx-proxy", "acme", "email") .. " "
    
    -- 域名处理
    local domains = uci:get("nginx-proxy", "acme", "domains") or ""
    for domain in domains:gmatch("%S+") do
        cmd = cmd .. "-d " .. domain .. " "
    end
    
    -- 验证方式
    if uci:get("nginx-proxy", "acme", "validation") == "http" then
        cmd = cmd .. "--webroot " .. uci:get("nginx-proxy", "acme", "webroot") .. " "
    else
        cmd = cmd .. "--dns " .. uci:get("nginx-proxy", "acme", "dns_provider") .. " "
        if uci:get("nginx-proxy", "acme", "dns_provider") == "custom" then
            cmd = cmd .. "--yes-I-know-dns-manual-mode-enough-go-ahead-please "
        end
    end
    
    return cmd
end

-- 更新证书路径
function update_cert_paths()
    local main_domain = (uci:get("nginx-proxy", "acme", "domains") or ""):match("%S+")
    if main_domain then
        main_domain = main_domain:gsub("^%*%.", "")
        uci:set("nginx-proxy", "ssl", "cert_path", "/etc/ssl/acme/"..main_domain.."_fullchain.cer")
        uci:set("nginx-proxy", "ssl", "key_path", "/etc/ssl/acme/"..main_domain..".key")
        uci:commit("nginx-proxy")
    end
end

-- 定时任务管理
function m.on_commit(self)
    if uci:get("nginx-proxy", "acme", "enabled") == "1" then
        -- 添加每日续期检查
        sys.call("echo '0 3 * * * /usr/lib/acme/acme.sh --cron' >> /etc/crontabs/root")
        sys.call("/etc/init.d/cron restart")
    else
        -- 移除定时任务
        sys.call("sed -i '/acme.sh --cron/d' /etc/crontabs/root")
    end
end

-- 输入验证
function m.validate(self)
    if uci:get("nginx-proxy", "acme", "validation") == "dns" then
        local provider = uci:get("nginx-proxy", "acme", "dns_provider")
        if provider ~= "custom" and #uci:get("nginx-proxy", "acme", "api_key") == 0 then
            return nil, translate("API key required for selected DNS provider")
        end
    end
    return true
end

return m
