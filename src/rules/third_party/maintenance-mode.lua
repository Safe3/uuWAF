--[[
规则名称: 站点维护模式
过滤阶段: 请求阶段
危险等级: 低危
规则描述: 将站点置为维护模式，返回“网页正在维护”的自定义页面。
--]]

-- 检查是否启用维护模式的条件（可以根据需求自定义，以下为示例）
local maintenance_mode = true  -- 可以通过配置文件或其他方式动态控制

if maintenance_mode then
    -- 设置自定义的维护页面 HTML 内容
    local maintenance_html = [[<!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>网页正在维护</title>
        <style>
            * {margin: 0; padding: 0; box-sizing: border-box;}
            body {
                min-height: 100vh;
                background: linear-gradient(120deg, #e0c3fc, #8ec5fc);
                display: flex;
                align-items: center;
                justify-content: center;
                font-family: -apple-system, BlinkMacSystemFont, sans-serif;
            }
            .glass {
                background: rgba(255, 255, 255, 0.25);
                backdrop-filter: blur(15px);
                border-radius: 30px;
                border: 1px solid rgba(255, 255, 255, 0.3);
                box-shadow: 0 8px 32px rgba(31, 38, 135, 0.15);
                padding: 40px;
                width: 90%;
                max-width: 480px;
                text-align: center;
                position: relative;
            }
            .icon {
                width: 80px;
                height: 80px;
                margin: 0 auto 20px;
            }
            h1 {
                color: #4a4a4a;
                font-size: 28px;
                font-weight: 600;
                margin-bottom: 15px;
            }
            .message {
                color: #666;
                font-size: 16px;
                line-height: 1.6;
                margin: 15px 0;
            }
            .provider {
                color: #666;
                font-size: 12px;
                position: absolute;
                bottom: -30px;
                left: 0;
                right: 0;
                text-align: center;
            }
            .provider strong {
                color: #5856d6;
            }
        </style>
    </head>
    <body>
        <div class="glass">
            <div class="icon">
                <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M12 22c5.5-4 8-8 8-12V5l-8-3-8 3v5c0 4 2.5 8 8 12z" stroke="#6e8efb" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
                    <path d="M9 12l2 2 4-4" stroke="#a777e3" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
            </div>
            <h1>网页正在维护</h1>
            <p class="message">抱歉，当前网页正在维护中，请稍后访问。</p>
            <div class="provider">维护通知由 <strong>南墙 WAF</strong> 提供</div>
        </div>
    </body>
    </html>]]

    ngx.header.content_type = "text/html; charset=utf-8"

    -- 输出维护页面并终止请求处理
    ngx.print(maintenance_html)
    return ngx.exit(ngx.HTTP_OK)  -- 使用 ngx.HTTP_OK 结束请求，避免传递到源站
end

return false  -- 未启用维护模式，不拦截请求
