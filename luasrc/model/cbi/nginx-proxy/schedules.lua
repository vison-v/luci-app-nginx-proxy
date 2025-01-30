local m, s, o

m = Map("nginx-proxy", translate("Scheduled Tasks"), 
    translate("Manage automated certificate renewal schedules"))

s = m:section(TypedSection, "schedules", translate("Cron Jobs"))
s.template = "cbi/tblsection"
s.addremove = true
s.anonymous = false

o = s:option(Value, "cron", translate("Cron Expression"))
o.datatype = "string"
o.rmempty = false
o.description = translate("Example: 0 3 * * * (daily at 3am)")

o = s:option(Value, "command", translate("Command"))
o.default = "/usr/lib/acme/acme.sh --cron"
o.readonly = true

return m
