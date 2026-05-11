# JNI_OnLoad `.dynsym` 地址篡改技术方案

`jnionload` 模块用于演示一种 Android Native 入口保护技术：在 `.so` 加载过程中，利用 `.init_array` 先于 `JNI_OnLoad` 执行的时机，动态修改内存中 `.dynsym` 符号表里 `JNI_OnLoad` 的 `st_value`，从而让 Android Runtime 后续通过 `dlsym(handle, "JNI_OnLoad")` 查询到一个伪装入口 `fake_JNI_OnLoad`，再由伪装入口执行保护逻辑并委托到真正的 `real_JNI_OnLoad`。

> 本模块仅用于 Android 安全研究、加固原理学习和自有 App 防护验证。请勿用于未授权场景。

---

## 1. 技术目标

传统 JNI 初始化流程中，`System.loadLibrary()` 加载 `.so` 后，ART 会通过 `dlsym()` 查找导出的 `JNI_OnLoad` 并调用。常规保护逻辑如果直接写在 `JNI_OnLoad` 中，静态分析者很容易定位真实入口，也容易针对 `JNI_OnLoad` 做 Hook。

本方案的目标是：

1. **隐藏真实 JNI 初始化逻辑**：公开导出的 `JNI_OnLoad` 只作为 fallback，真正逻辑放在 `real_JNI_OnLoad`。
2. **重定向 Runtime 查询结果**：在 ART 调用 `dlsym("JNI_OnLoad")` 之前，提前修改 `.dynsym` 中 `JNI_OnLoad` 的 `st_value`。
3. **实现入口包装层**：让 Runtime 实际进入 `fake_JNI_OnLoad`，在其中执行环境检测、解密、完整性校验等逻辑。
4. **保留兼容 fallback**：如果 patch 失败，原始 `JNI_OnLoad` 仍可委托到 `real_JNI_OnLoad`，避免 App 直接崩溃。

---

## 2. Android 加载时序

核心依赖点是：**`.init_array` 先于 `JNI_OnLoad` 执行**。

```text
System.loadLibrary("jnionload")
    ↓
ART NativeLoader / linker64
    ↓
linker mmap libjnionload.so
    ↓
解析 ELF / Program Header / Dynamic Section
    ↓
执行重定位
    ↓
调用 .init_array 构造函数
    ↓
init_patch_dynsym()
    ├── 获取自身 so base
    ├── 解析 ELF 动态段
    ├── 定位 .dynsym / .dynstr
    ├── 查找 JNI_OnLoad 符号
    └── 修改 JNI_OnLoad.st_value → fake_JNI_OnLoad offset
    ↓
返回 linker / ART
    ↓
ART 执行 dlsym(handle, "JNI_OnLoad")
    ↓
dlsym 从 .dynsym 读到已修改的 st_value
    ↓
调用 fake_JNI_OnLoad(vm, reserved)
    ↓
fake_JNI_OnLoad 执行保护逻辑
    ↓
委托 real_JNI_OnLoad(vm, reserved)
```

---

## 3. ELF `.dynsym` 符号结构

ELF64 的动态符号项结构如下：

```c
typedef struct {
    Elf64_Word    st_name;    // 符号名在 .dynstr 中的偏移
    unsigned char st_info;    // bind + type
    unsigned char st_other;   // visibility
    Elf64_Half    st_shndx;   // section index
    Elf64_Addr    st_value;   // 关键：符号虚拟地址/相对 so base 偏移
    Elf64_Xword   st_size;    // 符号大小
} Elf64_Sym;
```

本方案只修改 `JNI_OnLoad` 符号项中的 `st_value`：

```text
修改前：
JNI_OnLoad.st_value = original_JNI_OnLoad_offset

修改后：
JNI_OnLoad.st_value = fake_JNI_OnLoad_offset
```

其他字段如 `st_name`、`st_info`、`st_other`、`st_shndx`、`st_size` 均保持不变。

---

## 4. 当前模块实现结构

核心文件：

```text
jnionload/src/main/cpp/jni_onload_tamper.c
```

主要函数：

| 函数 | 作用 |
|---|---|
| `init_patch_dynsym()` | `.init_array` 构造函数，加载时自动执行 |
| `patch_jni_onload_dynsym()` | 核心 patch 流程，解析 ELF 并修改 `.dynsym` |
| `get_self_base()` | 通过 `dladdr()` 获取当前 `.so` 加载基址 |
| `get_nsyms_from_gnu_hash()` | 解析 `DT_GNU_HASH` 获取 `.dynsym` 安全遍历上限 |
| `get_nsyms_from_hash()` | 解析传统 `DT_HASH` 获取符号数量 |
| `get_readable_mapping_end()` | 从 `/proc/self/maps` 判断地址所在可读映射边界 |
| `is_range_readable()` | 判断指定内存区间是否可读 |
| `fake_JNI_OnLoad()` | 篡改后的伪装 JNI 入口 |
| `real_JNI_OnLoad()` | 真正的 JNI 初始化逻辑 |
| `JNI_OnLoad()` | 对外导出的原始符号，patch 失败时 fallback |

---

## 5. 核心实现流程

### 5.1 `.init_array` 触发

使用 constructor 属性把函数放入 `.init_array`：

```c
__attribute__((constructor(101)))
static void init_patch_dynsym(void) {
    patch_jni_onload_dynsym();
}
```

该函数会在 `JNI_OnLoad` 之前由 linker 调用。

### 5.2 获取自身 `.so` 基址

```c
static void* get_self_base(void) {
    Dl_info info;
    if (dladdr((const void*)get_self_base, &info) != 0) {
        return info.dli_fbase;
    }
    return NULL;
}
```

`dli_fbase` 即当前 so 的加载基址。

### 5.3 解析 ELF Header 和 Program Header

从 base 起始地址读取 `Elf64_Ehdr`，再通过 `e_phoff` 遍历 `Elf64_Phdr`：

```c
Elf64_Ehdr* ehdr = (Elf64_Ehdr*)base;
Elf64_Phdr* phdr = (Elf64_Phdr*)((uint8_t*)base + ehdr->e_phoff);
```

找到 `PT_DYNAMIC`：

```c
if (phdr[i].p_type == PT_DYNAMIC) {
    dyn = (Elf64_Dyn*)((uint8_t*)base + phdr[i].p_vaddr);
}
```

### 5.4 解析 Dynamic Section

需要关注的 dynamic tag：

| Tag | 作用 |
|---|---|
| `DT_SYMTAB` | `.dynsym` 地址 |
| `DT_STRTAB` | `.dynstr` 地址 |
| `DT_STRSZ` | `.dynstr` 大小 |
| `DT_GNU_HASH` | GNU hash 表，用于计算符号数量 |
| `DT_HASH` | SysV hash 表，用于计算符号数量 |

Android linker 对 `.dynamic` 中的 `d_ptr` 可能已经做过重定位，所以实现中同时尝试：

```text
1. d_ptr 原始值
2. base + d_ptr
```

并通过 `/proc/self/maps` 判断哪个地址可读。

### 5.5 GNU Hash 解析注意点

ELF64 `.gnu.hash` 格式为：

```text
uint32_t nbuckets
uint32_t symndx
uint32_t maskwords
uint32_t shift2
Elf64_Addr bloom[maskwords]
uint32_t buckets[nbuckets]
uint32_t chain[]
```

注意：

```text
ELF64 的 bloom 是 Elf64_Addr[]，不是 uint32_t[]
```

因此 buckets 地址必须这样计算：

```c
uintptr_t buckets_addr =
    (uintptr_t)gnu_hash + 16 + ((uintptr_t)maskwords * sizeof(Elf64_Addr));
```

chain 下标也不是直接使用 symbol index，而是：

```c
chain_index = symbol_index - symndx;
```

当前实现中加入了：

- `.gnu.hash` header sanity check
- buckets 可读性检查
- chain 可读性检查
- 65536 次 guard limit，避免异常数据导致无限循环

### 5.6 安全遍历 `.dynsym`

为了避免 crash，遍历符号时会做多层边界检查：

1. `.dynsym` 地址必须位于可读 mapping 中。
2. `.dynstr` 地址必须位于可读 mapping 中。
3. `DT_STRSZ` 必须合法，否则 fallback 到 mapping 剩余大小。
4. `sym_cnt` 不得超过 `.dynsym` mapping 能容纳的最大符号数。
5. 每个 `dynsym[i]` 都必须可读。
6. `st_name` 必须小于 `.dynstr` 大小。
7. 比较符号名时不用无界 `strcmp()`，而是结合剩余长度做 `memcmp()`。

示意：

```c
Elf64_Word name_offset = dynsym[i].st_name;
if (name_offset == 0 || name_offset >= dynstr_size) {
    continue;
}

const char* name = dynstr + name_offset;
size_t remain = dynstr_size - name_offset;
const char expected[] = "JNI_OnLoad";

if (remain >= sizeof(expected) &&
    memcmp(name, expected, sizeof(expected) - 1) == 0 &&
    name[sizeof(expected) - 1] == '\0') {
    // found
}
```

---

## 6. 修改 `JNI_OnLoad.st_value`

找到符号后，计算伪装入口相对 base 的偏移：

```c
uintptr_t fake_offset = (uintptr_t)&fake_JNI_OnLoad - (uintptr_t)base;
```

然后定位 `st_value` 所在页：

```c
uintptr_t target_page = ((uintptr_t)&dynsym[i].st_value) & ~((uintptr_t)0xFFF);
size_t page_size = sysconf(_SC_PAGESIZE);
```

修改页权限：

```c
mprotect((void*)target_page, page_size, PROT_READ | PROT_WRITE);
```

写入新值：

```c
dynsym[i].st_value = fake_offset;
```

恢复只读：

```c
mprotect((void*)target_page, page_size, PROT_READ);
```

---

## 7. 伪装入口与真实入口

### 7.1 `fake_JNI_OnLoad`

`fake_JNI_OnLoad` 是篡改后的实际入口。当前示例中保留了保护阶段的框架日志：

```text
Phase 1: Environment checks
  - Frida detection
  - Debugger detection
  - Root detection
  - Emulator detection

Phase 2: Decryption / Deobfuscation
  - String decryption
  - Code unpacking

Phase 3: Integrity checks
  - CRC monitor
  - Inline hook detection
  - GOT/PLT integrity

Phase 4: Delegating to real JNI_OnLoad
```

最终调用：

```c
return real_JNI_OnLoad(vm, reserved);
```

### 7.2 `real_JNI_OnLoad`

真实 JNI 初始化逻辑放在这里，例如：

- `GetEnv`
- `FindClass`
- `RegisterNatives`
- 初始化 native 全局状态

当前 demo 未注册实际 native 方法，只返回 `JNI_VERSION_1_6`。

### 7.3 原始 `JNI_OnLoad`

原始导出的 `JNI_OnLoad` 保留 fallback：

```c
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    return real_JNI_OnLoad(vm, reserved);
}
```

如果 patch 成功，正常情况下不会进入这里；如果 patch 失败，则仍能完成 JNI 初始化。

---

## 8. 为什么 `.dynsym` 可以被修改？

`.dynsym` 通常位于只读的 LOAD segment 中。运行时可能是 `r--p` 或 `r-xp`，直接写会触发 SIGSEGV。

本方案通过 `mprotect()` 临时修改页面权限：

```text
原权限：R-- / R-X
临时：RW-
写入 st_value
恢复：R--
```

需要注意：

- `mprotect` 以页为单位生效。
- 地址必须按页对齐。
- 某些 Android 版本或加固环境可能限制对代码/只读段执行 `mprotect`。
- 如果目标页包含其他只读数据，恢复权限需要谨慎。当前 demo 恢复为 `PROT_READ`。

---

## 9. 日志验证

运行 App 后过滤 logcat：

```text
JniOnLoadTamper
JniOnLoadLibrary
MainActivity
```

成功时会看到：

```text
[init_array] +++ .init_array executing +++
[patch] Self base address: ...
[patch] Found PT_DYNAMIC ...
[patch] DT_SYMTAB: ...
[patch] DT_STRTAB: ...
[patch] DT_STRSZ: ...
[patch] DT_GNU_HASH: nsyms = ...
[patch] Found 'JNI_OnLoad' at symbol index ...
[patch] ★★★ st_value PATCHED: ... -> ... ★★★
[init_array] .dynsym patch completed successfully
[fake_JNI_OnLoad] +++ Wrapper JNI_OnLoad called +++
[real_JNI_OnLoad] Real JNI_OnLoad executing
```

失败但 fallback 正常时会看到：

```text
[init_array] .dynsym patch FAILED — JNI_OnLoad will NOT be redirected
[JNI_OnLoad] WARNING: Original JNI_OnLoad called directly!
[real_JNI_OnLoad] Real JNI_OnLoad executing
```

---

## 10. 已处理的稳定性问题

开发过程中针对常见 crash 点做了修复：

### 10.1 ELF typedef 冲突

问题：手动定义 `Elf64_Sym` 等结构体会和系统 `<elf.h>` 冲突。

处理：直接 `#include <elf.h>`，使用系统定义。

### 10.2 `.dynamic d_ptr` 地址误判

问题：某些环境中 `d_ptr` 已经是绝对地址，再 `+ base` 会访问非法地址。

处理：同时尝试 `d_ptr` 和 `base + d_ptr`，用 `/proc/self/maps` 判断地址可读性。

### 10.3 `.gnu.hash` 解析错误

问题：ELF64 的 bloom filter 被错误当作 `uint32_t[]`，导致 buckets/chain 地址计算错误。

处理：按 `Elf64_Addr[]` 计算 bloom 大小，并修正 chain 下标。

### 10.4 `strcmp()` 越界

问题：符号名指针异常时，`strcmp()` 可能越过 `.dynstr` 边界。

处理：使用 `DT_STRSZ` 和 `memcmp()` 做有界比较。

---

## 11. 构建与运行

构建 native 模块：

```bash
./gradlew :jnionload:externalNativeBuildDebug
```

构建并安装示例 App：

```bash
./gradlew assembleDebug
```

App 中触发加载：

```kotlin
JniOnLoadLibrary.init()
```

---

## 12. 技术收益与局限

### 收益

- 增加静态分析门槛：导出的 `JNI_OnLoad` 不再是实际执行路径。
- 增加 Hook 成本：直接 Hook 原始 `JNI_OnLoad` 不一定命中真实入口。
- 提供更早的初始化时机：`.init_array` 可在 JNI 入口前执行准备工作。
- 支持灵活路由：可根据环境选择进入真实入口、空入口或失败路径。

### 局限

- 强依赖 linker 和 ELF 加载行为。
- 对 Android 版本、ROM、NDK 链接参数有兼容性要求。
- 修改只读段可能被安全策略、SELinux 或加固环境限制。
- 高级分析者仍可通过动态调试、linker trace、内存 diff 等方式发现 patch 行为。
- 本 demo 重点展示技术链路，反调试、反 Frida、完整性校验等均为 stub，需要按业务场景补齐。

---

## 13. 安全合规

本模块仅建议用于：

- 自有 App 的安全防护研究
- Android Native 加固技术学习
- 安全课程或实验室环境
- 授权测试环境

请勿用于未授权 App、第三方应用篡改、绕过检测或攻击行为。

---

## 14. License

本模块随项目使用 MIT License，详见根目录 [LICENSE](../LICENSE)。
