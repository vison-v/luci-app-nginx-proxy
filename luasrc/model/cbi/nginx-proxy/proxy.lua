local uci = luci.model.uci.cursor()
local fs = require "nixio.fs"
local sys = require "luci.sys"

m = Map("nginx-proxy", translate("Reverse Proxy Configuration"),
    translate("Configure domain-based reverse proxy rules. Each rule requires a unique domain configuration."))

-- 代理规则主配置节
s = m:section(TypedSection, "proxy", translate("Proxy Rules"))
s.template = "cbi/tblsection"
s.addremove = true
s.anonymous = false
s.sortable = true

-- 域名配置
domain = s:option(Value, "domain", translate("Domain Name"))
domain.datatype = "hostname"
domain.rmempty = false
domain.description = translate("Enter full domain (e.g. example.com or sub.example.com)")
function domain.validate(self, value, section)
    if not value:match("^[%w%-%.]+%.[%a]+$") then
        return nil, translate("Invalid domain format")
    end
    return value
end

-- 后端服务器配置
backend = s:option(Value, "backend", translate("Backend Server"))
backend.datatype = "uri"
backend.rmempty = false
backend.description = translate("Format: http://192.168.1.100:8080 or https://internal-server")
function backend.validate(self, value, section)
    if not value:match("^https?://") then
        return nil, translate("Must start with http:// or https://")
    end
    return value
end

-- 监听端口配置
port = s:option(Value, "port", translate("Listen Port"))
port.datatype = "port"
port.default = "80"
port.rmempty = false
port.description = translate("Standard ports: 80 (HTTP) or 443 (HTTPS)")

-- IP协议版本选项
ipv4 = s:option(Flag, "ipv4", translate("Enable IPv4"))
ipv4.default = "1"
ipv4.rmempty = false
ipv4.description = translate("Listen on IPv4 addresses")

ipv6 = s:option(Flag, "ipv6", translate("Enable IPv6"))
ipv6.default = "1"
ipv6.rmempty = false
ipv6.description = translate("Listen on IPv6 addresses")

-- 高级选项
adv = s:option(DummyValue, "advanced", translate("Advanced Settings"))
adv.template = "nginx-proxy/adv_options"

-- 自定义验证逻辑
function m.validate(self)
    local errs = {}
    uci:foreach("nginx-proxy", "proxy", function(section)
        if section.domain and section.backend then
            -- 检查端口冲突
            local others = uci:get_all("nginx-proxy", section[".name"])
            for _, s in pairs(others) do
                if s[".type"] == "proxy" and s.port == section.port then
                    if s.domain ~= section.domain then
                        table.insert(errs, translatef("Port %s conflict between %s and %s", 
                            section.port, section.domain, s.domain))
                    end
                end
            end
        end
    end)
    
    if #errs > 0 then
        return nil, errs
    end
    return true
end

-- 配置保存后操作
function m.on_commit(self)
    -- 自动生成配置文件
    luci.sys.call("/usr/libexec/nginx-proxy/generate-config >/dev/null 2>&1")
end

return m
