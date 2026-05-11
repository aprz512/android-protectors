# Android Protectors

Android Protectors 是一个用于研究和演示 Android Native 保护技术的示例项目。当前重点模块是 `jnionload`，实现了基于 ELF `.dynsym` 的 `JNI_OnLoad` 入口地址篡改方案，用于展示 Android linker 加载 `.so` 时的初始化顺序、动态符号表解析、内存权限修改以及 JNI 入口路由。

> 说明：本项目用于 Android 安全研究、加固原理学习和防护技术验证，请仅在合法授权的环境中使用。

## 项目结构

```text
android-protectors/
├── app/                  # 示例 Android App，用于触发和验证保护模块
├── jnionload/            # JNI_OnLoad 篡改技术模块
│   ├── readme.md         # 技术原理说明
│   └── src/main/cpp/     # Native 实现
├── gradle/               # Gradle Version Catalog
├── build.gradle.kts      # 根 Gradle 配置
└── settings.gradle.kts   # 模块配置
```

## 当前功能

### 1. `jnionload` 模块

`jnionload` 模块实现了一个完整的 `JNI_OnLoad` `.dynsym` 地址篡改流程：

1. 通过 `__attribute__((constructor))` 注册 `.init_array` 构造函数。
2. Android linker 在调用 `JNI_OnLoad` 之前先执行 `.init_array`。
3. 构造函数解析当前 `.so` 的 ELF Header 和 Program Header。
4. 定位 `PT_DYNAMIC`，解析 `DT_SYMTAB`、`DT_STRTAB`、`DT_STRSZ`、`DT_GNU_HASH` / `DT_HASH`。
5. 在 `.dynsym` 中查找导出的 `JNI_OnLoad` 符号。
6. 使用 `mprotect` 临时修改 `.dynsym` 所在页权限。
7. 将 `JNI_OnLoad` 的 `st_value` 从原始函数地址改为 `fake_JNI_OnLoad`。
8. linker 后续通过 `dlsym(handle, "JNI_OnLoad")` 查询时，会拿到被篡改后的入口。
9. `fake_JNI_OnLoad` 先执行保护逻辑，再委托给 `real_JNI_OnLoad`。

### 2. 示例 App

`app` 模块依赖 `:jnionload`，在 `MainActivity` 中调用：

```kotlin
JniOnLoadLibrary.init()
```

该调用会触发：

```text
System.loadLibrary("jnionload")
    ↓
linker 加载 libjnionload.so
    ↓
执行 .init_array
    ↓
篡改 .dynsym 中 JNI_OnLoad 的 st_value
    ↓
dlsym 查询 JNI_OnLoad
    ↓
实际进入 fake_JNI_OnLoad
    ↓
委托 real_JNI_OnLoad
```

## 关键文件

| 文件 | 说明 |
|---|---|
| `jnionload/src/main/cpp/jni_onload_tamper.c` | 核心 Native 实现 |
| `jnionload/src/main/cpp/CMakeLists.txt` | CMake 构建配置 |
| `jnionload/src/main/java/com/demo/jnionload/JniOnLoadLibrary.kt` | Kotlin 加载入口 |
| `app/src/main/java/com/demo/android_protectors/MainActivity.kt` | 示例调用入口 |
| `jnionload/readme.md` | `.dynsym` 篡改技术原理说明 |

## 构建环境

- Android Studio
- Android Gradle Plugin `9.0.1`
- Gradle Wrapper
- CMake `3.22.1`
- Android NDK
- minSdk `24`
- compileSdk `36.1`

## 构建方式

在项目根目录执行：

```bash
./gradlew assembleDebug
```

仅构建 native 模块：

```bash
./gradlew :jnionload:externalNativeBuildDebug
```

## 运行验证

安装并运行 `app` 后，使用 logcat 过滤以下 tag：

```text
JniOnLoadTamper
JniOnLoadLibrary
MainActivity
```

如果篡改成功，会看到类似日志：

```text
[init_array] +++ .init_array executing +++
[patch] Self base address: ...
[patch] DT_SYMTAB: ...
[patch] DT_STRTAB: ...
[patch] DT_GNU_HASH: nsyms = ...
[patch] Found 'JNI_OnLoad' at symbol index ...
[patch] ★★★ st_value PATCHED: ... -> ... ★★★
[fake_JNI_OnLoad] +++ Wrapper JNI_OnLoad called +++
[real_JNI_OnLoad] Real JNI_OnLoad executing
```

如果看到：

```text
[JNI_OnLoad] WARNING: Original JNI_OnLoad called directly!
```

说明 `.dynsym` patch 没有生效，程序会走 fallback 路径，仍然调用 `real_JNI_OnLoad`。

## 实现注意点

- Android linker 对 `.dynamic` 中 `d_ptr` 的处理在不同环境下可能存在差异，代码中同时兼容 `d_ptr` 已重定位和未重定位两种情况。
- `.gnu.hash` 在 ELF64 中的 bloom filter 是 `Elf64_Addr[]`，不是 `uint32_t[]`。
- 遍历 `.dynsym` 和 `.dynstr` 时需要结合 `/proc/self/maps`、`DT_STRSZ` 和边界检查，避免越界访问导致 SIGSEGV。
- 修改 `.dynsym` 前需要对目标页执行 `mprotect(PROT_READ | PROT_WRITE)`。
- 修改完成后恢复页面为只读，降低异常风险。

## 安全与合规

本项目代码仅用于：

- Android Native 加固机制学习
- ELF/linker 行为研究
- 自有 App 的安全防护验证
- 安全课程、实验室或授权测试环境

请勿将本项目用于未授权的应用篡改、绕过检测或攻击行为。

## License

当前未指定开源许可证。如需对外发布，请根据使用场景补充合适的 LICENSE 文件。
