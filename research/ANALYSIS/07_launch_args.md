# 07 · 启动参数（绕过启动器）

启动器实际传给游戏的命令行（用户实测抓取）：

```
-region eu -lan en -selfregion EU -resolution 0 -upscale 0
-launcherpath launcher.exe -ctrltype XBOX
-launcherroot "C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\launcher"
```

以下全部对照二进制核实，并补上了启动器没传的两个参数。

---

## 1. 解析器 `launcher_parse_commandline` @ `0x140027510`

```c
cfg = new(0xE0); memset(cfg, 0, 0xE0);
launcher_config_init(cfg);              // 填入 10 个选项的【名字】
cfg[6] = ".";                           // +0x48 安装根目录，默认当前目录
for (i = 0; i < argc; ++i)
    if (argv[i][0] == '-')
        for (j = 0; j < 10; ++j)
            if (strcmp(slot[j].name, argv[i] + 1) == 0) {
                if (argv[i+1]) slot[j].value = strdup(argv[i+1]);
                break;
            }
        // 未匹配的选项静默跳过
g_launcher_config = cfg;
```

要点：

- 语法是 **`-name value`，两个独立 argv 项**，不支持 `-name=value`。
- 名字比较是 `strcmp`，**精确且区分大小写**，只剥掉一个前导 `-`。
- 无法识别的选项**静默忽略**，不报错。
- `g_launcher_config` 是**指向堆结构的指针**，不是结构本身。

> ⚠️ **`cfg[6]` 默认是 `"."`，且没有任何地方用 `-launcherroot` 覆盖它。**
> `font_load_xpr` @ `0x140042C60` 用它拼出 `<root>\FONT\<name>.xpr`，
> 所以**进程的工作目录必须是 `mgspw\`**，否则字体加载会失败。
> 直接启动 exe 时这是最容易踩的一条。

## 2. 选项表（`launcher_config_init` @ `0x1400276D0`）

结构里每个选项占 16 字节：名字在 `+N`，值在 `+N+8`。

| 值偏移 | 选项 | 访问器 | 取值语义 |
|---|---|---|---|
| `+0x48` | `launcherpath` | `launcher_get_launcherpath` | 原样字符串 |
| `+0x58` | `launcherroot` | `launcher_get_launcherroot` | 原样字符串 |
| `+0x68` | `lan` | `lang_get_language_id` @ `0x140027B40` | 见 §3 |
| `+0x78` | `region` | *（未追到访问器，由联网/区域代码直接读）* | |
| `+0x88` | `selfregion` | *（同上）* | |
| `+0x98` | `ctrltype` | `launcher_get_ctrltype` @ `0x140027D00` | 见 §4 |
| `+0xA8` | `invited` | `launcher_get_invited` | 原样字符串 |
| `+0xB8` | `resolution` | `launcher_get_resolution_flag` | 布尔：值以 `1` 开头为真 |
| `+0xC8` | `movie` | `launcher_get_movie_flag` | 布尔：值以 `1` 开头为真 |
| `+0xD8` | `upscale` | `launcher_get_upscale` | `0`/`1`/`2`/`3`，其余及 NULL → 0 |

**`invited` 和 `movie` 启动器没有传**，但解析器支持。

## 3. `-lan`：唯一会把游戏搞坏的参数

`lang_get_language_id` @ `0x140027B40`：

| 值 | id |
|---|---|
| `en` | 0 |
| `fr` | 1 |
| `gr` | 2（德语） |
| `it` | 3 |
| `sp` | 4 |
| `pt` | **4** |
| `jp` | 6 |
| NULL 或任何其他值 | **6** |

两条要命的推论：

1. **`pt` 和 `sp` 都返回 4** —— 这是「葡萄牙语占用西班牙语槽」的**二进制侧
   直接证据**（此前 01 号文档只从文件数据推出该结论）。
2. **拼错或省略 `-lan` 会静默落到 6（日语）**。而 id 6 会让
   `path_resolve_install` 指向 `/JPN/disc0_rel`、让 `font_init_load_all`
   去加载 `00c7c9f9.xpr` / `001cbbd1.xpr` —— 这些在 Steam 版**都不存在**
   （见 05 号文档 §1）。所以 `-lan` 必须显式给出且拼对。

## 4. `-ctrltype`：按键图标集

`launcher_get_ctrltype` @ `0x140027D00`：

| 值 | id | 对应 `Text/*.txp` 图标包 |
|---|---|---|
| `PS4` | 0 | `005318e4.txp` |
| `PS5` | 1 | `005318e5.txp` |
| `XS` | 2 | `0082988a.txp` |
| `NX` | 3 | `008299c5.txp` |
| `KBD` | 4 | `008299c5.txp` |
| NULL 或其他 | 2 | `0082988a.txp` |

> 启动器传的 **`XBOX` 并不在匹配表里**，落到默认分支 2 —— 与 `XS` 同义。
> 真正的 Xbox 记号是 `XS`。

图标包的选择在 `ui_texture_request_by_ctrltype` @ `0x14003B520`，
这也补全了 05 号文档 §5 里「四个同尺寸 `.txp` 是手柄变体」的映射关系。

## 5. 直接启动（绕过启动器）

按代码推导的最小命令行——**工作目录必须是 `mgspw\`**：

```powershell
cd "C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
& ".\METAL GEAR SOLID PEACE WALKER.exe" -lan en -region eu -selfregion EU -ctrltype XS
```

- `-lan` 必给（否则落日语，见 §3）。
- `-region` / `-selfregion` 的读取点未追到，保守起见照启动器原样给。
- `-ctrltype` 可省（默认即 `XS`），按手柄类型改。
- `-resolution` / `-upscale` / `-movie` / `-invited` / `-launcherpath` /
  `-launcherroot` 省略后分别落到 false / 0 / false / NULL / NULL / NULL，
  游戏侧不依赖它们启动。

> 未实测。`-region` / `-selfregion` 的消费方还没反，不能保证省略它们也没事，
> 所以上面保留了这两项。

## 6. 待办

- [ ] 追 `+0x78`（region）与 `+0x88`（selfregion）的读取点，确认能否省略
- [ ] 实测最小命令行能否正常进游戏
