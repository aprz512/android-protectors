/**
 * jni_onload_tamper.c
 *
 * ============================================================================
 * JNI_OnLoad .dynsym 地址篡改技术方案 — 完整实现
 * ============================================================================
 *
 * 技术原理：
 *   1. 利用 __attribute__((constructor)) 将 patch 函数放入 .init_array
 *   2. .init_array 在 JNI_OnLoad 之前被 linker 执行
 *   3. patch 函数解析自身的 ELF 头，找到 .dynsym section
 *   4. 遍历符号表找到 "JNI_OnLoad" 符号项
 *   5. 通过 mprotect 使 .dynsym 所在页可写
 *   6. 修改 st_value，将 JNI_OnLoad 从原始地址重定向到 fake_JNI_OnLoad
 *   7. 之后 linker 通过 dlsym 查找 JNI_OnLoad 时，读到的就是篡改后的地址
 *   8. fake_JNI_OnLoad 执行反检测逻辑后，调用 real_JNI_OnLoad 完成真正的注册
 *
 * 时间线：
 *   mmap 加载 → 重定位 → init_array (patch 发生在这里) → dlsym → 调用
 *                                        ★ 篡改 .dynsym
 */

#include <jni.h>
#include <elf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>
#include <sys/mman.h>
#include <unistd.h>
#include <android/log.h>
#include <errno.h>

/* ============================================================================
 * 日志宏
 * ============================================================================ */

#define LOG_TAG "JniOnLoadTamper"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/* ============================================================================
 * 仅补充系统 <elf.h> 中不包含的结构体
 * ============================================================================ */

/* GNU Hash Table Header — <elf.h> 中未定义 */
typedef struct {
    uint32_t nbuckets;
    uint32_t symndx;
    uint32_t maskwords;
    uint32_t shift2;
} GnuHashHeader;

/* ============================================================================
 * 常量定义
 * ============================================================================ */

#define DT_GNU_HASH   0x6ffffef5

/* ============================================================================
 * 前向声明
 * ============================================================================ */

/* 真正的 JNI_OnLoad 实现 — 由 wrapper 调用 */
static jint real_JNI_OnLoad(JavaVM* vm, void* reserved);

/* 伪装 JNI_OnLoad — 替换 .dynsym 中的 st_value 指向此处 */
__attribute__((visibility("default")))
jint fake_JNI_OnLoad(JavaVM* vm, void* reserved);

/* ============================================================================
 * 辅助函数: 获取自身 .so 的加载基址
 * 使用 dladdr 查询自身函数地址，dli_fbase 即为加载基址
 * ============================================================================ */
static void* get_self_base(void) {
    Dl_info info;
    if (dladdr((const void*)get_self_base, &info) != 0) {
        return info.dli_fbase;
    }
    return NULL;
}

/* ============================================================================
 * 辅助函数: 根据 .gnu.hash 计算动态符号表符号数量
 *
 * .gnu.hash 结构 (in-memory):
 *   [0] nbuckets
 *   [1] symndx      — 第一个参与哈希的符号索引
 *   [2] maskwords   — bloom filter word 数量 (64-bit ELF 上)
 *   [3] shift2
 *   [4 .. 4+maskwords-1]         bloom filter (Elf64_Xword 数组)
 *   [4+maskwords .. ]            buckets (nbuckets 个 uint32_t)
 *   [4+maskwords+nbuckets .. ]   chain (链式哈希条目)
 *
 * 总符号数 = symndx + chain_entries
 * chain_entries 由 bucket 最大值作为起始点，沿链走到 LSB=1 的结尾
 * ============================================================================ */
static uintptr_t get_readable_mapping_end(const void* addr) {
    if (addr == NULL) return 0;

    FILE* f = fopen("/proc/self/maps", "r");
    if (f == NULL) return 0;

    char line[256];
    uintptr_t check = (uintptr_t)addr;
    uintptr_t result = 0;

    while (fgets(line, sizeof(line), f)) {
        unsigned long start_ul, end_ul;
        char perms[5] = {0};
        if (sscanf(line, "%lx-%lx %4s", &start_ul, &end_ul, perms) == 3) {
            uintptr_t start = (uintptr_t)start_ul;
            uintptr_t end = (uintptr_t)end_ul;
            if (check >= start && check < end && perms[0] == 'r') {
                result = end;
                break;
            }
        }
    }

    fclose(f);
    return result;
}

static int is_range_readable(const void* addr, size_t size) {
    if (addr == NULL || size == 0) return 0;
    uintptr_t start = (uintptr_t)addr;
    uintptr_t end = get_readable_mapping_end(addr);
    return end != 0 && start <= end && size <= (end - start);
}

static uint32_t get_nsyms_from_gnu_hash(uint32_t* gnu_hash) {
    if (!is_range_readable(gnu_hash, 16)) {
        LOGW("[patch] .gnu.hash header is not readable");
        return 0;
    }

    uint32_t nbuckets  = gnu_hash[0];
    uint32_t symndx    = gnu_hash[1];
    uint32_t maskwords = gnu_hash[2];

    /* 基本 sanity check，避免损坏/误判地址导致越界 */
    if (nbuckets == 0 || nbuckets > 65536 || maskwords == 0 || maskwords > 65536) {
        LOGW("[patch] Invalid .gnu.hash header: nbuckets=%u symndx=%u maskwords=%u",
             nbuckets, symndx, maskwords);
        return 0;
    }

    /* ELF64 的 bloom filter 是 Elf64_Addr 数组，不是 uint32_t 数组。
     * 之前按 uint32_t 跳过 maskwords 会把 buckets 算错，导致 chain 越界崩溃。 */
    uintptr_t buckets_addr = (uintptr_t)gnu_hash + 16 + ((uintptr_t)maskwords * sizeof(Elf64_Addr));
    if (!is_range_readable((void*)buckets_addr, (size_t)nbuckets * sizeof(uint32_t))) {
        LOGW("[patch] .gnu.hash buckets are not readable");
        return 0;
    }

    uint32_t* buckets = (uint32_t*)buckets_addr;
    uint32_t* chain = buckets + nbuckets;

    uint32_t max_sym = 0;
    for (uint32_t i = 0; i < nbuckets; i++) {
        if (buckets[i] > max_sym) {
            max_sym = buckets[i];
        }
    }

    if (max_sym < symndx) {
        return symndx;
    }

    uint32_t chain_index = max_sym - symndx;
    for (uint32_t guard = 0; guard < 65536; guard++, chain_index++, max_sym++) {
        if (!is_range_readable(&chain[chain_index], sizeof(uint32_t))) {
            LOGW("[patch] .gnu.hash chain out of readable range");
            return 0;
        }
        if (chain[chain_index] & 1U) {
            return max_sym + 1;
        }
    }

    LOGW("[patch] .gnu.hash chain scan exceeded guard limit");
    return 0;
}

/* ============================================================================
 * 辅助函数: 根据 DT_HASH (旧式 SYSV hash) 获取符号数量
 * DT_HASH 结构:
 *   [0] nbucket
 *   [1] nchain    — 即符号表总条目数
 * ============================================================================ */
static uint32_t get_nsyms_from_hash(uint32_t* hash) {
    /* hash[1] = nchain = 符号表条目数 */
    return hash[1];
}

/* ============================================================================
 * 辅助函数: 验证内存区域是否可读
 * 通过尝试读取首字节来判断，避免访问越界导致 SIGSEGV
 * ============================================================================ */
static int is_memory_readable(const void* addr) {
    return get_readable_mapping_end(addr) != 0;
}

/* ============================================================================
 * 核心函数: 解析自身 ELF + 篡改 .dynsym 中 JNI_OnLoad 的 st_value
 *
 * 这是 .init_array 中执行的函数，在 JNI_OnLoad 被调用之前运行。
 *
 * 流程:
 *   1. 获取自身 module 基址
 *   2. 解析 ELF header → 遍历 program headers → 找到 PT_DYNAMIC
 *   3. 遍历 .dynamic section 获取 DT_SYMTAB, DT_STRTAB, DT_GNU_HASH/DT_HASH
 *   4. 在 .dynsym 中搜索 "JNI_OnLoad" 符号
 *   5. mprotect 使目标页可写
 *   6. 修改 st_value 指向 fake_JNI_OnLoad
 *   7. (可选) 恢复页面权限
 *
 * 返回值: 0 = 成功, -1 = 失败
 * ============================================================================ */
static int patch_jni_onload_dynsym(void) {
    /* === Step 1: 获取自身基址 === */
    void* base = get_self_base();
    if (base == NULL) {
        LOGE("[patch] Failed to get self base address");
        return -1;
    }
    LOGI("[patch] Self base address: %p", base);

    /* === Step 2: 解析 ELF header === */
    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)base;

    /* 验证 ELF magic */
    if (memcmp(ehdr->e_ident, "\x7f" "ELF", 4) != 0) {
        LOGE("[patch] Invalid ELF magic");
        return -1;
    }

    /* 只支持 64-bit */
    if (ehdr->e_ident[4] != 2) { /* ELFCLASS64 */
        LOGE("[patch] Not a 64-bit ELF");
        return -1;
    }

    /* === Step 3: 遍历 Program Headers 找到 PT_DYNAMIC === */
    Elf64_Phdr* phdr = (Elf64_Phdr*)((uint8_t*)base + ehdr->e_phoff);
    Elf64_Dyn*  dyn  = NULL;

    for (Elf64_Half i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn = (Elf64_Dyn*)((uint8_t*)base + phdr[i].p_vaddr);
            LOGI("[patch] Found PT_DYNAMIC at offset 0x%lx, vaddr 0x%lx",
                 (unsigned long)phdr[i].p_offset,
                 (unsigned long)phdr[i].p_vaddr);
            break;
        }
    }

    if (dyn == NULL) {
        LOGE("[patch] PT_DYNAMIC segment not found");
        return -1;
    }

    /* === Step 4: 遍历 .dynamic 获取关键表地址 ===
     *
     * 稳健策略：同时尝试 base + d_ptr 和直接使用 d_ptr，
     * 通过 is_memory_readable 验证哪个是正确的。
     * ============================================================================ */
    Elf64_Sym*  dynsym      = NULL;
    char*       dynstr      = NULL;
    size_t      dynstr_size = 0;
    uint32_t    sym_cnt     = 0;

    /* 先找 DT_SYMTAB 来确定 d_ptr 是绝对值还是偏移 */
    /* 同时收集所有需要的信息 */
    for (Elf64_Dyn* d = dyn; d->d_tag != DT_NULL; d++) {
        uintptr_t dptr = (uintptr_t)d->d_un.d_ptr;
        uintptr_t addr_offset = dptr + (uintptr_t)base;

        switch (d->d_tag) {
            case DT_SYMTAB:
                /* 尝试两种地址，优先用直接值 */
                if (is_memory_readable((void*)dptr)) {
                    dynsym = (Elf64_Sym*)dptr;
                    LOGI("[patch] DT_SYMTAB: %p (d_ptr raw)", (void*)dynsym);
                } else if (is_memory_readable((void*)addr_offset)) {
                    dynsym = (Elf64_Sym*)addr_offset;
                    LOGI("[patch] DT_SYMTAB: %p (base + d_ptr)", (void*)dynsym);
                }
                break;
            case DT_STRTAB:
                if (is_memory_readable((void*)dptr)) {
                    dynstr = (char*)dptr;
                    LOGI("[patch] DT_STRTAB: %p (d_ptr raw)", (void*)dynstr);
                } else if (is_memory_readable((void*)addr_offset)) {
                    dynstr = (char*)addr_offset;
                    LOGI("[patch] DT_STRTAB: %p (base + d_ptr)", (void*)dynstr);
                }
                break;
            case DT_STRSZ:
                dynstr_size = (size_t)d->d_un.d_val;
                LOGI("[patch] DT_STRSZ: %zu", dynstr_size);
                break;
            case DT_GNU_HASH: {
                uint32_t* hash = NULL;
                if (is_memory_readable((void*)dptr)) {
                    hash = (uint32_t*)dptr;
                } else if (is_memory_readable((void*)addr_offset)) {
                    hash = (uint32_t*)addr_offset;
                }
                if (hash != NULL) {
                    sym_cnt = get_nsyms_from_gnu_hash(hash);
                }
                LOGI("[patch] DT_GNU_HASH: nsyms = %u", sym_cnt);
                break;
            }
            case DT_HASH:
                if (sym_cnt == 0) {
                    uint32_t* hash = NULL;
                    if (is_memory_readable((void*)dptr)) {
                        hash = (uint32_t*)dptr;
                    } else if (is_memory_readable((void*)addr_offset)) {
                        hash = (uint32_t*)addr_offset;
                    }
                    if (hash != NULL) {
                        sym_cnt = get_nsyms_from_hash(hash);
                    }
                    LOGI("[patch] DT_HASH: nsyms = %u", sym_cnt);
                }
                break;
        }
    }

    if (dynsym == NULL || dynstr == NULL) {
        LOGE("[patch] .dynsym or .dynstr not found");
        return -1;
    }

    uintptr_t dynsym_end = get_readable_mapping_end(dynsym);
    uintptr_t dynstr_end = get_readable_mapping_end(dynstr);
    if (dynsym_end == 0 || dynstr_end == 0) {
        LOGE("[patch] .dynsym or .dynstr mapping is not readable");
        return -1;
    }

    if (dynstr_size == 0 || dynstr_size > (dynstr_end - (uintptr_t)dynstr)) {
        dynstr_size = dynstr_end - (uintptr_t)dynstr;
        LOGW("[patch] DT_STRSZ missing/invalid, fallback dynstr_size=%zu", dynstr_size);
    }

    uint32_t max_sym_by_mapping = (uint32_t)((dynsym_end - (uintptr_t)dynsym) / sizeof(Elf64_Sym));
    if (max_sym_by_mapping > 4096) {
        max_sym_by_mapping = 4096;
    }

    if (sym_cnt == 0 || sym_cnt > max_sym_by_mapping) {
        LOGW("[patch] Adjust nsyms from %u to safe limit %u", sym_cnt, max_sym_by_mapping);
        sym_cnt = max_sym_by_mapping;
    }

    /* === Step 5: 遍历 .dynsym 搜索 "JNI_OnLoad" === */
    for (uint32_t i = 0; i < sym_cnt; i++) {
        if (!is_range_readable(&dynsym[i], sizeof(Elf64_Sym))) {
            LOGW("[patch] dynsym[%u] is out of readable range, stop scanning", i);
            break;
        }

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
            Elf64_Addr original_st_value = dynsym[i].st_value;

            LOGI("[patch] Found 'JNI_OnLoad' at symbol index %u", i);
            LOGI("[patch]   st_name  = 0x%x  -> \"%s\"",   dynsym[i].st_name,  name);
            LOGI("[patch]   st_info  = 0x%02x (bind=%d, type=%d)",
                 dynsym[i].st_info,
                 dynsym[i].st_info >> 4,         /* STB_* */
                 dynsym[i].st_info & 0x0F);      /* STT_* */
            LOGI("[patch]   st_shndx = 0x%x",    dynsym[i].st_shndx);
            LOGI("[patch]   st_value = 0x%lx  <- 原始地址", (unsigned long)original_st_value);
            LOGI("[patch]   st_size  = 0x%lx",   (unsigned long)dynsym[i].st_size);

            /* 计算 fake_JNI_OnLoad 相对于基址的偏移 */
            uintptr_t fake_offset = (uintptr_t)&fake_JNI_OnLoad - (uintptr_t)base;
            LOGI("[patch]   fake_JNI_OnLoad offset = 0x%lx", (unsigned long)fake_offset);

            /* === Step 6: mprotect 使 .dynsym 所在页可写 === */
            uintptr_t target_page = ((uintptr_t)&dynsym[i].st_value) & ~((uintptr_t)0xFFF);
            size_t    page_size   = sysconf(_SC_PAGESIZE);

            LOGI("[patch] mprotect: making page %p RW", (void*)target_page);
            if (mprotect((void*)target_page, page_size,
                        PROT_READ | PROT_WRITE) != 0) {
                LOGE("[patch] mprotect(RW) failed: %s", strerror(errno));
                return -1;
            }

            /* === Step 7: 篡改 st_value === */
            dynsym[i].st_value = fake_offset;
            LOGI("[patch] ★★★ st_value PATCHED: 0x%lx -> 0x%lx ★★★",
                 (unsigned long)original_st_value,
                 (unsigned long)fake_offset);

            /* === Step 8: 恢复页面权限为只读 === */
            if (mprotect((void*)target_page, page_size, PROT_READ) != 0) {
                LOGW("[patch] mprotect(RO) failed: %s (non-critical)", strerror(errno));
            } else {
                LOGI("[patch] mprotect: page restored to RO");
            }

            /* === Step 9: 清理指令/数据 cache === */
            __builtin___clear_cache((char*)target_page,
                                    (char*)(target_page + page_size));

            LOGI("[patch] ===== Patch SUCCESS! JNI_OnLoad redirected to fake_JNI_OnLoad =====");
            return 0;
        }
    }

    LOGE("[patch] 'JNI_OnLoad' symbol NOT FOUND in .dynsym");
    return -1;
}

/* ============================================================================
 * init_array 构造函数 — linker 加载 .so 后最先执行
 *
 * 使用 __attribute__((constructor)) 确保该函数被放入 .init_array section，
 * linker 在完成重定位之后、调用 JNI_OnLoad 之前执行 .init_array 中的函数。
 * 优先级 101 确保它尽可能早执行（但仍晚于 C 运行时初始化）。
 * ============================================================================ */
__attribute__((constructor(101)))
static void init_patch_dynsym(void) {
    LOGI("==============================================");
    LOGI("[init_array] +++ .init_array executing +++");
    LOGI("[init_array] Patching .dynsym JNI_OnLoad entry...");
    LOGI("==============================================");

    if (patch_jni_onload_dynsym() == 0) {
        LOGI("[init_array] .dynsym patch completed successfully");
    } else {
        LOGE("[init_array] .dynsym patch FAILED — JNI_OnLoad will NOT be redirected");
    }
}

/* ============================================================================
 * fake_JNI_OnLoad — 伪装 JNI_OnLoad 函数
 *
 * 由于 .dynsym 中的 st_value 已被篡改指向此函数，linker 通过 dlsym
 * 查找 JNI_OnLoad 时实际获得的是这个函数的地址。它在调用真正的 JNI_OnLoad
 * 之前执行反检测、反调试、环境检查等保护逻辑。
 *
 * 典型阶段:
 *   阶段 1: 环境检测 (Frida/Debugger/Root 检测)
 *   阶段 2: 解密/解混淆 (字符串解密、代码段解包)
 *   阶段 3: 安装完整性检查 (Hook 自身关键函数)
 *   阶段 4: 调用真正的 JNI_OnLoad
 * ============================================================================ */
__attribute__((visibility("default")))
jint fake_JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGI("==============================================");
    LOGI("[fake_JNI_OnLoad] +++ Wrapper JNI_OnLoad called +++");
    LOGI("[fake_JNI_OnLoad] This proves .dynsym patch is working!");
    LOGI("==============================================");

    /* ================================================================
     * 阶段 1: 环境检测
     * ================================================================ */

    LOGI("[fake_JNI_OnLoad] Phase 1: Environment checks...");

    /* 1.1 Frida 检测 — 检查常见 Frida 端口、线程、内存特征 */
    /* (此处为占位，实际应实现: 扫描 /proc/self/maps 中的 frida 特征、
     *  检查默认端口 27042/27043、扫描 named pipe 等) */
    LOGI("[fake_JNI_OnLoad]   Frida detection: PASS (stub)");

    /* 1.2 调试器检测 — 检查 ptrace/TracerPid */
    /* (实际实现: 读取 /proc/self/status 中的 TracerPid 字段) */
    LOGI("[fake_JNI_OnLoad]   Debugger detection: PASS (stub)");

    /* 1.3 Root 检测 — 检查 su 二进制、Magisk 特征、系统属性 */
    /* (实际实现: 检查 /system/bin/su, /system/xbin/su, ro.build.tags 等) */
    LOGI("[fake_JNI_OnLoad]   Root detection: PASS (stub)");

    /* 1.4 模拟器检测 — 检查 /dev/socket/qemud、CPU 特性、传感器数据 */
    /* (实际实现: 读取 ro.kernel.qemu, 检查硬件传感器等) */
    LOGI("[fake_JNI_OnLoad]   Emulator detection: PASS (stub)");

    LOGI("[fake_JNI_OnLoad] Phase 1 complete — environment is CLEAN");

    /* ================================================================
     * 阶段 2: 解密/解混淆
     * ================================================================ */

    LOGI("[fake_JNI_OnLoad] Phase 2: Decryption / Deobfuscation...");

    /* 2.1 解密加密的字符串常量 */
    /* (实际实现: XOR/AES 解密 .rodata 中的加密字符串) */
    LOGI("[fake_JNI_OnLoad]   String decryption: DONE (stub)");

    /* 2.2 解包隐藏的代码段 */
    /* (实际实现: 解密并恢复被加密的 .text 子段) */
    LOGI("[fake_JNI_OnLoad]   Code unpacking: DONE (stub)");

    LOGI("[fake_JNI_OnLoad] Phase 2 complete");

    /* ================================================================
     * 阶段 3: 安装完整性检查
     * ================================================================ */

    LOGI("[fake_JNI_OnLoad] Phase 3: Installing integrity checks...");

    /* 3.1 代码段 CRC 校验线程 */
    /* (实际实现: 创建后台线程定期校验 .text 段哈希) */
    LOGI("[fake_JNI_OnLoad]   CRC integrity monitor: INSTALLED (stub)");

    /* 3.2 内联 Hook 检测 (检查自身关键函数序言是否被修改) */
    LOGI("[fake_JNI_OnLoad]   Inline hook detection: INSTALLED (stub)");

    /* 3.3 GOT/PLT 表完整性校验 */
    LOGI("[fake_JNI_OnLoad]   GOT/PLT integrity: VERIFIED (stub)");

    LOGI("[fake_JNI_OnLoad] Phase 3 complete");

    /* ================================================================
     * 阶段 4: 调用真正的 JNI_OnLoad
     * ================================================================ */

    LOGI("[fake_JNI_OnLoad] Phase 4: Delegating to real JNI_OnLoad...");
    jint result = real_JNI_OnLoad(vm, reserved);
    LOGI("[fake_JNI_OnLoad] real_JNI_OnLoad returned: %d", result);

    LOGI("[fake_JNI_OnLoad] ===== Wrapper JNI_OnLoad finished =====");
    return result;
}

/* ============================================================================
 * real_JNI_OnLoad — 真正的 JNI_OnLoad 实现
 *
 * 这是实际执行 JNI 方法注册的地方。在正常流程中，此函数只会被
 * fake_JNI_OnLoad 调用（如果 patch 成功），绝不会被 linker 直接调用。
 *
 * 如需注册 native 方法，在此函数中实现。
 * ============================================================================ */
static jint real_JNI_OnLoad(JavaVM* vm, void* reserved) {
    (void)reserved; /* unused */

    LOGI("[real_JNI_OnLoad] Real JNI_OnLoad executing");

    JNIEnv* env = NULL;
    jint    ret = (*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6);

    if (ret != JNI_OK) {
        LOGE("[real_JNI_OnLoad] GetEnv failed: %d", ret);
        return JNI_ERR;
    }

    if (env == NULL) {
        LOGE("[real_JNI_OnLoad] env is NULL");
        return JNI_ERR;
    }

    /* ================================================================
     * 在此处注册 native 方法
     * ================================================================
     *
     * 示例:
     *
     *   jclass clazz = (*env)->FindClass(env, "com/demo/jnionload/JniOnLoadLibrary");
     *   if (clazz == NULL) {
     *       LOGE("[real_JNI_OnLoad] FindClass failed");
     *       return JNI_ERR;
     *   }
     *
     *   JNINativeMethod methods[] = {
     *       {"nativeInit",    "()V",     (void*)native_init},
     *       {"nativeProcess", "([B)[B",  (void*)native_process},
     *   };
     *
     *   (*env)->RegisterNatives(env, clazz, methods,
     *       sizeof(methods) / sizeof(methods[0]));
     */

    LOGI("[real_JNI_OnLoad] Native methods registered (none configured)");
    LOGI("[real_JNI_OnLoad] Real JNI_OnLoad finished");

    return JNI_VERSION_1_6;
}

/* ============================================================================
 * JNI_OnLoad — 公开导出的 JNI_OnLoad 符号
 *
 * ★ 重要: 此函数在正常流程中永远不会被 linker 调用！
 *
 * linker 通过 dlsym(handle, "JNI_OnLoad") 查找该符号时，
 * 读取的是 .dynsym 中已被篡改的 st_value，因此实际调用的是 fake_JNI_OnLoad。
 *
 * 此函数仅作为 fallback — 当 .dynsym patch 失败时，linker 仍能通过
 * 原始 st_value 找到这里，此时直接委托给 real_JNI_OnLoad。
 * ============================================================================ */
__attribute__((visibility("default")))
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGW("[JNI_OnLoad] WARNING: Original JNI_OnLoad called directly!");
    LOGW("[JNI_OnLoad] This means the .dynsym patch did NOT work.");
    LOGW("[JNI_OnLoad] Falling back to real_JNI_OnLoad directly...");

    /* 直接委派给真正的 JNI_OnLoad，跳过所有保护检测 */
    return real_JNI_OnLoad(vm, reserved);
}
