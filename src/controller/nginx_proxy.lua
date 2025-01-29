module("luci.controller.nginx_proxy", package.seeall)  

function index()  
    entry({"admin", "services", "nginx_proxy"}, cbi("nginx_proxy"), _("Nginx Reverse Proxy"), 60)  
    entry({"admin", "services", "nginx_proxy", "logs"}, call("view_logs"), _("View Logs"), 70)  
end  

function view_logs()  
    local logs = io.popen("cat /var/log/nginx/access.log 2>&1"):read("*all")  
    luci.template.render("nginx_proxy_logs", {logs=logs})  
end
