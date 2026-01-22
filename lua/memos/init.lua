---@diagnostic disable: undefined-global
local M = {}
M.tags = {}
M.tags_loaded = false
M.tags_loading = false
M.tag_view_state = {}

local extract_memos
local refresh_all_tag_views

local default_config = {
    base_url = '',
    token = '',
    page_size = 20,
    list_preview_length = 80,
    default_visibility = 'PUBLIC',
    curl_path = 'curl',
    memo_filetype = 'markdown',
    memo_format_on_save = true,
    format_timeout_ms = 5000,
    create_body = nil,
    update_body = nil,
}

local function notify(msg, level)
    vim.notify(msg, level or vim.log.levels.INFO, { title = 'memos.nvim' })
end

local function normalize_url(base, path)
    local trimmed = base:gsub('/+$', '')
    local suffix = path
    if not suffix:match('^/') then
        suffix = '/' .. suffix
    end
    return trimmed .. suffix
end

local function memo_resource(memo)
    if type(memo) ~= 'table' then
        return nil
    end
    if type(memo.name) == 'string' and memo.name ~= '' then
        if memo.name:match('^/') then
            return memo.name
        end
        return '/' .. memo.name
    end
    if memo.id ~= nil then
        return '/memos/' .. tostring(memo.id)
    end
    if memo.uid ~= nil then
        return '/memos/' .. tostring(memo.uid)
    end
    return nil
end

local function buffer_name_for_memo(memo, is_new)
    if is_new then
        return 'memos://new'
    end
    local resource = memo_resource(memo)
    if resource then
        return 'memos://' .. resource:gsub('^/', '')
    end
    return 'memos://memo'
end

local function build_create_body(content, cfg)
    if type(cfg.create_body) == 'function' then
        return cfg.create_body(content, cfg)
    end
    local body = { content = content }
    if cfg.default_visibility and cfg.default_visibility ~= '' then
        body.visibility = cfg.default_visibility
    end
    return body
end

local function build_update_body(content, cfg, memo)
    if type(cfg.update_body) == 'function' then
        return cfg.update_body(content, cfg, memo)
    end
    return { content = content }
end

local function normalize_tag(tag)
    if type(tag) == 'table' then
        tag = tag.name or tag.tag
    end
    if type(tag) ~= 'string' or tag == '' then
        return nil
    end
    tag = tag:match('^%s*(.-)%s*$')
    if tag:sub(1, 1) == '#' then
        tag = tag:sub(2)
    end
    if tag == '' then
        return nil
    end
    return tag
end

local function add_tags(tag_set, tags)
    if type(tags) ~= 'table' then
        return
    end
    local function add(tag)
        local normalized = normalize_tag(tag)
        if normalized then
            tag_set[normalized] = true
        end
    end
    local has_array = false
    for _, tag in ipairs(tags) do
        has_array = true
        add(tag)
    end
    for key, tag in pairs(tags) do
        if type(key) == 'string' then
            add(key)
        elseif not has_array and tag ~= nil and type(tag) ~= 'boolean' then
            add(tag)
        end
    end
end

local function extract_tags_from_text(text)
    local tags = {}
    if type(text) ~= 'string' then
        return tags
    end
    for tag in text:gmatch('#([%w_-]+)') do
        tags[#tags + 1] = tag
    end
    return tags
end
    return tags
end

local function update_tag_cache(memo)
    if type(memo) ~= 'table' then
        return
    end
    if memo.tags ~= nil then
        add_tags(M.tags, memo.tags)
    end
    if memo.relations ~= nil and type(memo.relations) == 'table' then
        add_tags(M.tags, memo.relations)
    end
    if type(memo.content) == 'string' then
        add_tags(M.tags, extract_tags_from_text(memo.content))
    end
end

local function find_tag_completion()
    local line = vim.api.nvim_get_current_line()
    local col = vim.fn.col('.')
    local start = col
    while start > 1 and line:sub(start - 1, start - 1):match('[%w_-]') do
        start = start - 1
    end
    if start > 1 and line:sub(start - 1, start - 1) == '#' then
        local base = line:sub(start, col - 1)
        return start, base
    end
    return nil, nil
end

local function tag_candidates(prefix)
    local items = {}
    if type(M.tags) ~= 'table' then
        return items
    end
    local lookup = M.tags
    local needle = prefix or ''
    for tag in pairs(lookup) do
        if needle == '' or tag:sub(1, #needle) == needle then
            items[#items + 1] = tag
        end
    end
    table.sort(items)
    return items
end

local function maybe_trigger_tag_complete()
    if vim.fn.pumvisible() == 1 then
        return
    end
    local start, base = find_tag_completion()
    if not start then
        return
    end
    local items = tag_candidates(base)
    if #items == 0 then
        return
    end
    vim.fn.complete(start, vim.tbl_map(function(item)
        return { word = item, abbr = '#' .. item }
    end, items))
end

local function request_async(method, path, body, callback)
    local cfg = M.config
    if not cfg or cfg.base_url == '' then
        callback(nil, 'memos: base_url is not configured')
        return
    end

    local url = normalize_url(cfg.base_url, path)
    local cmd = { cfg.curl_path, '-sS', '-L', '-X', method, url, '-H', 'Accept: application/json' }
    if cfg.token and cfg.token ~= '' then
        table.insert(cmd, '-H')
        table.insert(cmd, 'Authorization: Bearer ' .. cfg.token)
    end
    if body ~= nil then
        table.insert(cmd, '-H')
        table.insert(cmd, 'Content-Type: application/json')
        table.insert(cmd, '-d')
        table.insert(cmd, vim.json.encode(body))
    end

    local stdout_chunks = {}
    local stderr_chunks = {}
    local function collect(target, data)
        if not data or #data == 0 then
            return
        end
        local joined = table.concat(data, '\n')
        if joined ~= '' then
            target[#target + 1] = joined
        end
    end

    local job_id = vim.fn.jobstart(cmd, {
        stdout_buffered = true,
        stderr_buffered = true,
        on_stdout = function(_, data) collect(stdout_chunks, data) end,
        on_stderr = function(_, data) collect(stderr_chunks, data) end,
        on_exit = function(_, code)
            vim.schedule(function()
                local output = table.concat(stdout_chunks, '\n')
                if code ~= 0 then
                    local err = table.concat(stderr_chunks, '\n')
                    if err == '' then
                        err = output
                    end
                    callback(nil, err)
                    return
                end
                if output == '' then
                    callback({}, nil)
                    return
                end
                local trimmed = output:gsub('^%s+', ''):gsub('%s+$', '')
                if trimmed == '' then
                    callback({}, nil)
                    return
                end
                if trimmed:sub(1, 1) == '<' then
                    callback(nil, 'memos: non-JSON response (HTML) for ' .. url .. ': ' .. trimmed:sub(1, 200))
                    return
                end
                local start = trimmed:find('[%[{]')
                local last = nil
                for i = #trimmed, 1, -1 do
                    local ch = trimmed:sub(i, i)
                    if ch == '}' or ch == ']' then
                        last = i
                        break
                    end
                end
                local candidate = trimmed
                if start and last and last >= start then
                    candidate = trimmed:sub(start, last)
                end
                local ok, data = pcall(vim.json.decode, candidate)
                if not ok then
                    callback(nil, 'memos: failed to decode JSON response: ' .. candidate:sub(1, 200))
                    return
                end
                callback(data, nil)
            end)
        end,
    })

    if job_id <= 0 then
        callback(nil, 'memos: failed to start curl job')
    end
end

local function fetch_tag_cache_from_api_async()
    local cfg = M.config
    if not cfg or cfg.base_url == '' then
        M.tags_loading = false
        return
    end
    local pages = 0
    local function fetch_page(page_token)
        local path = '/memos?pageSize=' .. tostring(cfg.page_size)
        if page_token and page_token ~= '' then
            path = path .. '&pageToken=' .. vim.uri_encode(page_token)
        end
        request_async('GET', path, nil, function(payload, err)
            if err then
                notify(err, vim.log.levels.ERROR)
                M.tags_loading = false
                return
            end
            local memos = extract_memos(payload)
            for _, memo in ipairs(memos) do
                update_tag_cache(memo)
            end
            refresh_all_tag_views()
            local next_token = payload and (payload.nextPageToken or payload.next_page_token)
            if not next_token or next_token == '' then
                M.tags_loading = false
                refresh_all_tag_views()
                return
            end
            pages = pages + 1
            if pages > 1000 then
                notify('memos: tag cache pagination limit exceeded', vim.log.levels.WARN)
                M.tags_loading = false
                refresh_all_tag_views()
                return
            end
            fetch_page(next_token)
        end)
    end
    fetch_page(nil)
end

local function ensure_tag_cache()
    if M.tags_loaded or M.tags_loading then
        return
    end
    M.tags_loaded = true
    M.tags_loading = true
    fetch_tag_cache_from_api_async()
end

function _G.memos_tag_omnifunc(findstart, base)
    if findstart == 1 then
        ensure_tag_cache()
        local start = find_tag_completion()
        if not start then
            return -1
        end
        return start - 1
    end
    local prefix = base or ''
    if prefix:sub(1, 1) == '#' then
        prefix = prefix:sub(2)
    end
    ensure_tag_cache()
    local items = tag_candidates(prefix)
    return vim.tbl_map(function(item)
        return { word = item, abbr = '#' .. item }
    end, items)
end

local function apply_tag_highlight(buf)
    vim.api.nvim_set_hl(0, 'MemosTag', { link = 'Special', default = true })
    vim.api.nvim_buf_call(buf, function()
        vim.cmd([[syntax match MemosTag /#[[:alnum:]_-]\+/]])
    end)
end

local function request(method, path, body)
    local cfg = M.config
    if not cfg or cfg.base_url == '' then
        return nil, 'memos: base_url is not configured'
    end

    local url = normalize_url(cfg.base_url, path)
    local cmd = { cfg.curl_path, '-sS', '-L', '-X', method, url, '-H', 'Accept: application/json' }
    if cfg.token and cfg.token ~= '' then
        table.insert(cmd, '-H')
        table.insert(cmd, 'Authorization: Bearer ' .. cfg.token)
    end
    if body ~= nil then
        table.insert(cmd, '-H')
        table.insert(cmd, 'Content-Type: application/json')
        table.insert(cmd, '-d')
        table.insert(cmd, vim.json.encode(body))
    end

    local output = vim.fn.system(cmd)
    if vim.v.shell_error ~= 0 then
        return nil, output
    end
    if output == '' then
        return {}, nil
    end

    local trimmed = output:gsub('^%s+', ''):gsub('%s+$', '')
    if trimmed == '' then
        return {}, nil
    end
    if trimmed:sub(1, 1) == '<' then
        return nil, 'memos: non-JSON response (HTML) for ' .. url .. ': ' .. trimmed:sub(1, 200)
    end

    local start = trimmed:find('[%[{]')
    local last = nil
    for i = #trimmed, 1, -1 do
        local ch = trimmed:sub(i, i)
        if ch == '}' or ch == ']' then
            last = i
            break
        end
    end

    local candidate = trimmed
    if start and last and last >= start then
        candidate = trimmed:sub(start, last)
    end

    local ok, data = pcall(vim.json.decode, candidate)
    if not ok then
        return nil, 'memos: failed to decode JSON response: ' .. candidate:sub(1, 200)
    end
    return data, nil
end

extract_memos = function(payload)
    if type(payload) ~= 'table' then
        return {}
    end
    if type(payload.memos) == 'table' then
        return payload.memos
    end
    if type(payload.items) == 'table' then
        return payload.items
    end
    if type(payload) == 'table' and payload[1] ~= nil then
        return payload
    end
    return {}
end

local function extract_memo(payload)
    if type(payload) ~= 'table' then
        return nil
    end
    if type(payload.memo) == 'table' then
        return payload.memo
    end
    if type(payload.memos) == 'table' and payload.memos[1] then
        return payload.memos[1]
    end
    return payload
end

local function memo_summary(memo, max_len)
    local content = memo.content or memo.snippet or ''
    content = content:gsub('[\r\n]+', ' ')
    content = content:gsub('%s+', ' ')
    if #content > max_len then
        content = content:sub(1, max_len - 1) .. '...'
    end
    return content
end

local function format_memo_line(memo, max_len)
    local id = memo.id or memo.uid or memo.name or ''
    local summary = memo_summary(memo, max_len)
    return string.format('%s | %s', id, summary)
end

local fetch_memo_details
local open_memo_buffer
local close_window

local function open_memo_list(memos)
    local cfg = M.config
    local lines = {}
    local lookup = {}
    for _, memo in ipairs(memos or {}) do
        update_tag_cache(memo)
        lines[#lines + 1] = format_memo_line(memo, cfg.list_preview_length)
        lookup[#lines] = memo
    end

    local buf = vim.api.nvim_create_buf(false, true)
    vim.api.nvim_buf_set_lines(buf, 0, -1, false, lines)
    vim.bo[buf].buftype = 'nofile'
    vim.bo[buf].bufhidden = 'wipe'
    vim.bo[buf].swapfile = false
    vim.bo[buf].filetype = 'memos-list'

    vim.api.nvim_buf_set_var(buf, 'memos_items', lookup)

    vim.keymap.set('n', 'q', function()
        close_window(vim.api.nvim_get_current_win())
    end, { buffer = buf, desc = 'Close memos list' })
    vim.keymap.set('n', 'r', function() M.open_list() end, { buffer = buf, desc = 'Refresh memos list' })
    vim.keymap.set('n', 'n', function() M.new_memo() end, { buffer = buf, desc = 'New memo' })
    vim.keymap.set('n', '<CR>', function()
        local line = vim.api.nvim_win_get_cursor(0)[1]
        local items = vim.api.nvim_buf_get_var(buf, 'memos_items')
        local memo = items[line]
        if not memo then
            notify('No memo on this line', vim.log.levels.WARN)
            return
        end
        memo = fetch_memo_details(memo)
        open_memo_buffer(memo, false)
    end, { buffer = buf, desc = 'Open memo' })

    vim.api.nvim_set_current_buf(buf)
    vim.bo[buf].modified = false
    return buf
end

open_memo_buffer = function(memo, is_new)
    local buf = vim.api.nvim_create_buf(false, true)
    vim.api.nvim_buf_set_name(buf, buffer_name_for_memo(memo, is_new))
    vim.api.nvim_set_current_buf(buf)
    vim.bo[buf].modified = false

    local lines = {}
    if memo and memo.content then
        lines = vim.split(memo.content, '\n', { plain = true })
    end
    vim.api.nvim_buf_set_lines(buf, 0, -1, false, lines)

    vim.bo[buf].buftype = 'acwrite'
    vim.bo[buf].bufhidden = 'wipe'
    vim.bo[buf].swapfile = false
    vim.bo[buf].filetype = M.config.memo_filetype or 'markdown'
    apply_tag_highlight(buf)
    vim.bo[buf].omnifunc = 'v:lua.memos_tag_omnifunc'

    vim.api.nvim_create_autocmd('BufWriteCmd', {
        buffer = buf,
        callback = function() M.save_current() end,
        desc = 'Save memo via Memos API',
    })
    vim.api.nvim_create_autocmd('TextChangedI', {
        buffer = buf,
        callback = function()
            ensure_tag_cache()
            maybe_trigger_tag_complete()
        end,
        desc = 'Trigger tag completion for memos',
    })

    if is_new then
        vim.b[buf].memos_new = true
    else
        vim.b[buf].memos_new = false
    end
    if memo then
        vim.b[buf].memos_resource = memo_resource(memo)
        vim.b[buf].memos_visibility = memo.visibility
        update_tag_cache(memo)
    end
    vim.bo[buf].modified = false

    vim.keymap.set('n', '<leader>ms', function() M.save_current() end, { buffer = buf, desc = 'Save memo' })
    return buf
end

fetch_memo_details = function(memo)
    if memo and memo.content then
        return memo
    end
    local resource = memo_resource(memo)
    if not resource then
        return memo
    end
    local payload, err = request('GET', resource, nil)
    if err then
        notify(err, vim.log.levels.ERROR)
        return memo
    end
    return extract_memo(payload)
end

close_window = function(win)
    if win and vim.api.nvim_win_is_valid(win) then
        vim.api.nvim_win_close(win, true)
    end
end

local function maybe_format_buffer(buf)
    local cfg = M.config
    if not cfg.memo_format_on_save then
        return
    end
    if vim.bo[buf].filetype ~= (cfg.memo_filetype or 'markdown') then
        return
    end
    local ok, conform = pcall(require, 'conform')
    if not ok then
        return
    end
    pcall(conform.format, {
        bufnr = buf,
        async = false,
        lsp_fallback = true,
        timeout_ms = cfg.format_timeout_ms,
    })
end

M.tag_views = {}

local function build_tag_tree_data()
    local root = {}
    local keys = {}
    for tag in pairs(M.tags) do
        table.insert(keys, tag)
    end
    table.sort(keys)

    local function find_or_create(list, name, full_path)
        for _, n in ipairs(list) do
            if n.name == name then
                return n
            end
        end
        local n = {
            name = name,
            full_path = full_path,
            children = {},
            expanded = M.tag_view_state and M.tag_view_state[full_path] or false,
        }
        table.insert(list, n)
        return n
    end

    for _, tag in ipairs(keys) do
        local parts = {}
        for part in tag:gmatch("[^/]+") do
            table.insert(parts, part)
        end

        local current_list = root
        local path = ""
        for i, part in ipairs(parts) do
            path = path == "" and part or path .. "/" .. part
            local node = find_or_create(current_list, part, path)
            current_list = node.children
        end
    end
    return root
end

local function render_tags_buffer(buf)
    if not vim.api.nvim_buf_is_valid(buf) then return end
    
    local root = build_tag_tree_data()
    vim.api.nvim_buf_set_var(buf, 'memos_tag_tree', root)
    
    local lines = {}
    local lookup = {}

    local function traverse(nodes, depth)
        for _, node in ipairs(nodes) do
            local prefix = string.rep("  ", depth)
            local icon = "  "
            if #node.children > 0 then
                icon = node.expanded and "▼ " or "▶ "
            end
            table.insert(lines, prefix .. icon .. node.name)
            table.insert(lookup, node)
            if node.expanded then
                traverse(node.children, depth + 1)
            end
        end
    end

    if M.tags_loading and #root == 0 then
        lines = { "Loading tags..." }
    else
        traverse(root, 0)
        if #lines == 0 then
             lines = { "No tags found." }
        end
    end

    vim.api.nvim_set_option_value('modifiable', true, { buf = buf })
    vim.api.nvim_buf_set_lines(buf, 0, -1, false, lines)
    vim.api.nvim_set_option_value('modifiable', false, { buf = buf })
    vim.api.nvim_buf_set_var(buf, 'memos_tag_lookup', lookup)
end

refresh_all_tag_views = function()
    for buf, _ in pairs(M.tag_views) do
        if vim.api.nvim_buf_is_valid(buf) then
            vim.schedule(function()
                render_tags_buffer(buf)
            end)
        else
            M.tag_views[buf] = nil
        end
    end
end

function M.open_tags_view()
    ensure_tag_cache()

    local buf = vim.api.nvim_create_buf(false, true)
    vim.api.nvim_buf_set_name(buf, "memos://tags")
    vim.api.nvim_set_option_value('buftype', 'nofile', { buf = buf })
    vim.api.nvim_set_option_value('filetype', 'memos-tags', { buf = buf })
    vim.api.nvim_set_option_value('swapfile', false, { buf = buf })
    vim.api.nvim_set_option_value('bufhidden', 'wipe', { buf = buf })

    M.tag_views[buf] = true
    
    -- Cleanup on wipe
    vim.api.nvim_create_autocmd("BufWipeout", {
        buffer = buf,
        callback = function()
            M.tag_views[buf] = nil
        end
    })

    local function toggle()
        local line = vim.fn.line('.')
        local lookup = vim.api.nvim_buf_get_var(buf, 'memos_tag_lookup')
        if not lookup or #lookup == 0 then return end
        local node = lookup[line]
        if node and #node.children > 0 then
            node.expanded = not node.expanded
            if not M.tag_view_state then
                M.tag_view_state = {}
            end
            M.tag_view_state[node.full_path] = node.expanded
            render_tags_buffer(buf)
        end
    end

    local function select()
        local line = vim.fn.line('.')
        local lookup = vim.api.nvim_buf_get_var(buf, 'memos_tag_lookup')
        if not lookup or #lookup == 0 then return end
        local node = lookup[line]
        if node then
            close_window(vim.api.nvim_get_current_win())
            M.search("#" .. node.full_path)
        end
    end

    vim.keymap.set('n', '<Space>', toggle, { buffer = buf, silent = true })
    vim.keymap.set('n', '<Tab>', toggle, { buffer = buf, silent = true })
    vim.keymap.set('n', 'o', toggle, { buffer = buf, silent = true })
    vim.keymap.set('n', '<CR>', select, { buffer = buf, silent = true })
    vim.keymap.set('n', 'q', function()
        close_window(vim.api.nvim_get_current_win())
    end, { buffer = buf, silent = true })
    vim.keymap.set('n', '<Esc>', function()
        close_window(vim.api.nvim_get_current_win())
    end, { buffer = buf, silent = true })

    local width = 40
    local height = 20
    local ui = vim.api.nvim_list_uis()[1]
    local row = math.floor((ui.height - height) / 2)
    local col = math.floor((ui.width - width) / 2)

    local win_opts = {
        relative = 'editor',
        width = width,
        height = height,
        row = row,
        col = col,
        style = 'minimal',
        border = 'rounded',
        title = ' Tags ',
        title_pos = 'center',
    }

    local win = vim.api.nvim_open_win(buf, true, win_opts)
    
    -- Initial render
    render_tags_buffer(buf)
end

function M.open_list()
    local cfg = M.config
    local payload, err = request('GET', '/memos?pageSize=' .. tostring(cfg.page_size), nil)
    if err then
        notify(err, vim.log.levels.ERROR)
        return
    end

    local memos = extract_memos(payload)
    open_memo_list(memos)
end

function M.search(query)
    if type(query) ~= 'string' then
        return
    end
    local trimmed = query:match('^%s*(.-)%s*$')
    if not trimmed or trimmed == '' then
        notify('memos: empty search query', vim.log.levels.WARN)
        return
    end
    local cfg = M.config
    local path = '/memos?pageSize=' .. tostring(cfg.page_size) .. '&search=' .. vim.uri_encode(trimmed)
    local payload, err = request('GET', path, nil)
    if err then
        notify(err, vim.log.levels.ERROR)
        return
    end
    local memos = extract_memos(payload)
    if #memos == 0 then
        notify('No memos found for: ' .. trimmed, vim.log.levels.INFO)
        return
    end
    open_memo_list(memos)
end

function M.new_memo()
    open_memo_buffer(nil, true)
end

function M.save_current()
    local buf = vim.api.nvim_get_current_buf()
    local cfg = M.config
    maybe_format_buffer(buf)
    local content = table.concat(vim.api.nvim_buf_get_lines(buf, 0, -1, false), '\n')
    add_tags(M.tags, extract_tags_from_text(content))

    if vim.b[buf].memos_new then
        local body = build_create_body(content, cfg)
        local payload, err = request('POST', '/memos', body)
        if err then
            notify(err, vim.log.levels.ERROR)
            return
        end
        local memo = extract_memo(payload)
        if memo then
            vim.b[buf].memos_new = false
            vim.b[buf].memos_resource = memo_resource(memo)
            vim.b[buf].memos_visibility = memo.visibility
            vim.api.nvim_buf_set_name(buf, buffer_name_for_memo(memo, false))
        end
        vim.bo[buf].modified = false
        notify('Memo created')
        return
    end

    local resource = vim.b[buf].memos_resource
    if not resource or resource == '' then
        notify('memos: missing memo resource id', vim.log.levels.ERROR)
        return
    end

    local body = build_update_body(content, cfg, { name = resource })
    local _, err = request('PATCH', resource, body)
    if err then
        notify(err, vim.log.levels.ERROR)
        return
    end
    vim.bo[buf].modified = false
    notify('Memo updated')
end

function M.setup(opts)
    M.config = vim.tbl_deep_extend('force', default_config, opts or {})

    vim.api.nvim_create_user_command('Memos', function() M.open_list() end, {})
    vim.api.nvim_create_user_command('MemosNew', function() M.new_memo() end, {})
    vim.api.nvim_create_user_command('MemosSave', function() M.save_current() end, {})
    vim.api.nvim_create_user_command('MemosSearch', function(opts) M.search(opts.args) end, { nargs = '+' })
    vim.api.nvim_create_user_command('MemosTags', function() M.open_tags_view() end, {})
end

return M
