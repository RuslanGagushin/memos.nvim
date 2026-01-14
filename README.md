# memos.nvim

A small Neovim client for the Memos API. Browse, create, and edit memos without leaving Neovim.

## Features

- List memos from your Memos instance
- Open and edit a memo in a scratch buffer
- Create new memos
- Save via `:write` or `:MemosSave`
- Markdown filetype by default (works with renderers like markview.nvim)
- Optional format-on-save integration with conform.nvim

## Requirements

- Neovim 0.9+ (uses `vim.json`)
- `curl` in PATH
- A Memos instance and access token

## Installation

### mini.deps

```lua
MiniDeps.add({
  source = 'RuslanGagushin/memos.nvim',
})

require('memos').setup({
  base_url = 'https://memos.example.com/api/v1',
  token = 'YOUR_ACCESS_TOKEN',
})
```

### lazy.nvim

```lua
{
  'RuslanGagushin/memos.nvim',
  config = function()
    require('memos').setup({
      base_url = 'https://memos.example.com/api/v1',
      token = 'YOUR_ACCESS_TOKEN',
    })
  end,
}
```

## Setup

```lua
require('memos').setup({
  base_url = 'https://memos.example.com/api/v1',
  token = 'YOUR_ACCESS_TOKEN',
  page_size = 20,
  default_visibility = 'PUBLIC',
  memo_filetype = 'markdown',
  memo_format_on_save = true,
  format_timeout_ms = 5000,
})
```

## Commands

- `:Memos` - open memo list
- `:MemosNew` - create a new memo
- `:MemosSave` - save the current memo buffer

## Suggested mappings

```lua
vim.keymap.set('n', '<Leader>mm', '<Cmd>Memos<CR>', { desc = 'Memos list' })
vim.keymap.set('n', '<Leader>mn', '<Cmd>MemosNew<CR>', { desc = 'Memos new' })
vim.keymap.set('n', '<Leader>mS', '<Cmd>MemosSave<CR>', { desc = 'Memos save' })
```

## Troubleshooting

- If you see a non-JSON response (HTML), double-check that `base_url` includes `/api/v1`.
- Ensure your token is valid and that the instance is reachable.

## License

MIT
