local chunk = ngx.arg[1]
local eof = ngx.arg[2]

if ngx.ctx.buffered == nil then
    ngx.ctx.buffered = {}
end

if chunk ~= "" then
    table.insert(ngx.ctx.buffered, chunk)
    ngx.arg[1] = nil -- 清空当前 chunk
end

if eof then
    -- 将所有 chunk 拼接成完整的响应体
    local resp_body = table.concat(ngx.ctx.buffered)
    ngx.ctx.resp_body = resp_body
    ngx.ctx.buffered = nil

    -- 替换响应体为加密后的报文
    ngx.arg[1] = ngx.ctx.encrypted_body
end
