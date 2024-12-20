---
--- 
--- 
--- 修订日期: 2024/12/20
---

local ngx = ngx
local ngx_log = ngx.log
local ngx_ERR = ngx.ERR
local ngx_print = ngx.print
local ngx_exit = ngx.exit
local ngx_today = ngx.today
local ngx_kv = ngx.shared

local _M = {
    version = 1.7,
    name = "auth-plugin"  -- 插件名称
}

-- 配置
local valid_domains = {
    "test.com",        -- 需要保护的域名列表
    "test1.cn"
}

local valid_username = "admin"
local valid_password = "password123"  -- 强密码建议修改
local session_duration = 7200  -- 2小时，以秒为单位
local max_login_attempts = 5   -- 最大登录失败次数

-- 处理特殊字符函数，防止 HTML 注入
local function escape_html(str)
    if not str then return "" end
    local replacements = {
        ["&"] = "&amp;",
        ["<"] = "&lt;",
        [">"] = "&gt;",
        ['"'] = "&quot;",
        ["'"] = "&#39;",
    }
    return (str:gsub("[&<>'\"]", function(c) return replacements[c] end))
end

-- 登录页面HTML模板，带错误提示信息
local function get_login_page(req_uri, error_message)
    local escaped_error_message = escape_html(error_message or "")
    local form_action = escape_html(req_uri or "/")

    -- HTML部分拼接
    return [[
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>身份验证</title>
        <style>
            /* 通用样式保持简洁 */
            * {margin: 0; padding: 0; box-sizing: border-box;}
            body { min-height: 100vh; background: linear-gradient(120deg, #e0c3fc, #8ec5fc); display: flex; align-items: center; justify-content: center; font-family: -apple-system, BlinkMacSystemFont, sans-serif; }
            .glass { background: rgba(255, 255, 255, 0.25); backdrop-filter: blur(15px); border-radius: 30px; border: 1px solid rgba(255, 255, 255, 0.3); box-shadow: 0 8px 32px rgba(31, 38, 135, 0.15); padding: 40px; width: 90%; max-width: 480px; text-align: center; position: relative; }
            h1 {color: #4a4a4a; font-size: 28px; font-weight: 600; margin-bottom: 15px;}
            .error-message {color: #d9534f; font-size: 14px; margin-bottom: 20px;}
            label {display: block; text-align: left; margin-bottom: 10px; font-weight: bold; color: #555;}
            input[type="text"], input[type="password"] {width: 100%; padding: 12px; margin-bottom: 20px; border-radius: 15px; border: 1px solid rgba(255, 255, 255, 0.4); font-size: 14px; background: rgba(255, 255, 255, 0.2); color: #555;}
            input[type="submit"] {background: linear-gradient(45deg, #6e8efb, #a777e3); color: white; padding: 12px 35px; border-radius: 25px; font-weight: 500; border: none; cursor: pointer; font-size: 16px; transition: transform 0.3s ease, box-shadow 0.3s ease;}
            input[type="submit"]:hover {transform: translateY(-2px); box-shadow: 0 5px 15px rgba(110, 142, 251, 0.4);}
            .note {color: #666; font-size: 12px; margin-top: 20px;}
        </style>
    </head>
    <body>
        <div class="glass">
            <h1>身份验证</h1>
            ]] .. (escaped_error_message ~= "" and '<p class="error-message">' .. escaped_error_message .. '</p>' or "") .. [[
            <form method="POST" action="]] .. form_action .. [[">
                <label for="username">用户名</label>
                <input type="text" id="username" name="username" placeholder="输入用户名" required>
                <label for="password">密码</label>
                <input type="password" id="password" name="password" placeholder="输入密码" required>
                <input type="submit" value="登录">
            </form>
            <p class="note">您的访问受保护，请输入正确的账号密码。</p>
        </div>
    </body>
    </html>
    ]]
end

-- 校验登录请求
local function validate_login(waf)
    local form = waf.form["FORM"]
    if form then
        local username = form["username"]
        local password = form["password"]
        if username == valid_username and password == valid_password then
            return true
        end
    end
    return false
end

-- 请求阶段后过滤器
function _M.req_post_filter(waf)
    local host = waf.host
    local req_uri = waf.reqUri
    local method = waf.method

    -- 检查域名是否受保护
    local is_protected = false
    for _, domain in ipairs(valid_domains) do
        if string.lower(host) == string.lower(domain) then
            is_protected = true
            break
        end
    end

    if not is_protected then
        return
    end

    -- 检查登录失败的次数
    local login_attempts_key = "login_attempts:" .. waf.ip .. ":" .. host
    local login_attempts = ngx_kv.ipCache and ngx_kv.ipCache:get(login_attempts_key) or 0

    if login_attempts >= max_login_attempts then
        -- 直接拦截超出登录尝试次数的请求
        ngx_kv.ipBlock:incr(waf.ip, 1, 0)  -- 将IP拉入拦截列表
        waf.msg = "IP因登录失败次数过多已被拦截"
        waf.rule_id = 10001
        waf.deny = true
        return ngx_exit(403) -- 返回403 Forbidden
    end

    -- 校验会话是否已认证
    local session_key = "auth:" .. waf.ip .. ":" .. host -- 结合 IP 和 域名生成唯一会话
    local is_authenticated = ngx_kv.ipCache and ngx_kv.ipCache:get(session_key)

    if not is_authenticated then
        if method == "POST" then
            if validate_login(waf) then
                -- 登录成功：记录验证认证
                ngx_kv.ipCache:set(session_key, true, session_duration)
                ngx_kv.ipCache:delete(login_attempts_key) -- 重置失败次数
                return
            else
                -- 登录失败：记录失败次数
                login_attempts = login_attempts + 1
                ngx_kv.ipCache:set(login_attempts_key, login_attempts, 3600) -- 失败次数保存1小时
                
                -- 可选：输出登录失败提示（直接返回页面避免请求到原站）
                local error_message = "用户名或密码错误，请重试。"
                ngx.header.content_type = "text/html; charset=utf-8"
                return ngx.print(get_login_page(req_uri, error_message)) -- 使用直接返回页面
            end
        else
            -- 显示登录页面
            ngx.header.content_type = "text/html; charset=utf-8"
            return ngx.print(get_login_page(req_uri, nil)) -- 使用直接返回页面
        end
    end

    -- 已经认证，继续处理后续请求
end

return _M
