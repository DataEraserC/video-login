# video-login

Harness-independent, multi-channel login for video sites.

`video-login` obtains and stores the login cookies a downloader (yt-dlp and friends)
needs for sites that gate content behind an account. It knows nothing about dsh,
MCP, or any agent harness — it is a CLI plus a C shared library, and a host
integration is a thin JSON shim over one function.

```
vlogin channels                      # what can I log into, and how?
vlogin login start bilibili qr       # -> {"sessionId":…,"challenge":{…}}
vlogin login poll <sessionId>        # keep calling until result is done
vlogin import bilibili ./cookies.txt # store a finished credential
vlogin status                        # is anything still logged in?
vlogin export bilibili > jar.txt     # hand cookies to a downloader
```

## Why a separate tool

The original plugin had login hard-wired to one channel (bilibili) and one method
(QR). That does not survive contact with reality: sites offer different login
paths, and QR alone breaks on headless boxes, on accounts without a phone handy,
and for anything you would rather import from a browser you are already signed
into.

So the extension seam is the **product of two orthogonal dimensions**:

* **channel** — which site (`bilibili`, `douyin`, `youtube`, …)
* **method** — which login path (`qr`, `manual`, `sms`, `password`, `browser`)

A provider implements the methods it actually supports. The registry advertises
the full method enum with `implemented: false` where it does not, so a host can
render a complete picker and gets a structured refusal instead of a missing
button. Adding a site is one file; adding a method to a site is one `match` arm,
with no UI change as long as the method's `kind` is already known.

## Channels

| id | name | status |
|---|---|---|
| `bilibili` | 哔哩哔哩 | live QR (real `passport.bilibili.com` flow) |
| `douyin` | 抖音 | QR reserved; `manual` / `browser` live |
| `youtube` | YouTube | `manual` / `browser` live |
| `tencent` | 腾讯视频 | QR reserved (QQ); `manual` / `browser` live |
| `iqiyi` | 爱奇艺 | QR reserved; `manual` / `browser` live |
| `youku` | 优酷 | `manual` / `browser` live |
| `generic` | 其他站点 | `manual` / `browser` live — catch-all for unlisted hosts |

YouTube deliberately does **not** offer OAuth. A Google bearer token does not
authorize cookie-authenticated downloads, so a token would log you in and then
still fail at fetch time — worse than not offering it.

## Methods

| id | label | kind | host renders |
|---|---|---|---|
| `qr` | 扫码登录 | `Qr` | the QR image, then polls |
| `manual` | 手动导入 Cookie | `Import` | a textarea |
| `sms` | 短信验证码登录 | `Credential` | phone field, then code field |
| `password` | 账号密码登录 | `Credential` | username + password fields |
| `browser` | 从浏览器读取 | `Browse` | a "open browser" button |

`kind`, not `id`, drives rendering — so a new method needs no UI work.

## Storage

Everything lives under one root (`$VLOGIN_HOME`, else
`$XDG_DATA_HOME/video-login`, else `~/.local/share/video-login`):

The core knows none of its callers — not dsh, not the CLI. A harness that
keeps its state somewhere else exports that into `VLOGIN_HOME` before its first
call; the dsh plugin sets it to `$DSH_HOME/video-fetch`. Without one, the root
above applies, so the CLI and a Python script get the same default.

```
accounts/<channel>.json     account pool: labels, active pin, metadata
accounts/<channel>.jar.txt  active account's cookies, Netscape format
cookies/<channel>.json      legacy single-account file, read-only, migrated on load
sessions/<id>.json          in-flight login sessions, mode 0600
```

Sessions are files, not memory, because the flows that need them are multi-step
(QR poll, SMS send→verify) while the callers are one-shot CLI invocations and
stateless HTTP requests. A session has to outlive the process that created it.

Up to 10 accounts per channel. Downloads use the pinned account first and rotate
through the rest on failure.

## C ABI

Two symbols, JSON in, JSON out:

```c
const char *vlogin_version(void);
int64_t     vlogin_call(const char *request, char *out, uint64_t out_len);
```

The caller owns the output buffer; Rust only writes into it. There is
deliberately no `vlogin_string_free` — the usual alternative (Rust allocates,
host frees) requires the two allocators to agree and leaks on every forgetful
binding. `vlogin_call` returns the bytes needed **including** the trailing NUL,
or `-1` if `request` was null or not valid UTF-8. If the return is larger than
your buffer, grow it and call again.

Note the unit: the return value counts **bytes** (UTF-8), which is not what
`String.length` gives you in JS or `len()` in Python for non-ASCII labels. Compare
against bytes or you will loop forever on a short read.

`request` is `{"op": …, …}`. Ops:

| | | | |
|---|---|---|---|
| `channels` | `route` | `status` | `accounts` |
| `start` | `browse` | `poll` | `submit` |
| `import` | `check` | `pin` | `logout` |
| `clear` | `export` | `materialize` | `cancel` |
| `sweep` | | | |

Every response is `{"ok":true,"result":…}` or
`{"ok":false,"error":{"kind":…,"message":…}}`, where `kind` is one of
`channel`, `cookie`, `http`, `io`, `json`, `other`.

## Security

Cookies are credentials, so the ABI is shaped to keep them out of host surfaces:

* No response ever contains a cookie value. The only op that returns secret text
  is `export`, and it exists to be written into a downloader's cookie file — not
  to be displayed.
* The one cookie-derived value a host may render is a **count**
  (`AccountView.cookie_count`), so a UI can say "12 cookies" without handling the
  text.
* Errors carry status codes and truncated response bodies only.
* Session files are `0600`; account stores are written with restrictive
  permissions and are excluded from version control.

`browser` extraction launches a Chromium-family browser with
`--remote-debugging-port` and reads `Network.getAllCookies` over loopback
DevTools, rather than decrypting the profile's `Cookies` SQLite — the latter
needs SQLite plus a D-Bus secret service plus AES-CBC, and breaks outright when
the browser and the extraction step are on different machines.

## Build

```sh
nix build            # or: cargo build --release
nix develop          # cargo, rustc, clippy, rustfmt, rust-analyzer, just
cargo test
```

Workspace crates:

* `vlogin-core` — providers, cookie codec, account store, HTTP, sessions
* `vlogin-abi` — the cdylib (`libvlogin.so`)
* `vlogin-cli` — the `vlogin` binary

## License

MIT — see [LICENSE](./LICENSE).
