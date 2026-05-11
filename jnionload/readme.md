.dynsym 中 JNI_OnLoad 地址篡改的完整技术原理
一、整体流程图
plain
┌─────────────────────────────────────────────────────────────────────┐
│                        Android Linker 加载 .so 流程                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  System.loadLibrary("target")                                       │
│       ↓                                                             │
│  linker: mmap .so → 解析 ELF → 重定位                                │
│       ↓                                                             │
│  linker: 执行 .init_array[] 中的所有函数                              │
│       ↓                                                             │
│  ┌─────────────────────────────────────────────┐                    │
│  │ init_array[N]: sub_2327C8()                  │                   │
│  │     ↓                                        │                   │
│  │ sub_232A90():                                │                   │
│  │     1. 解析自身 ELF 头                        │                   │
│  │     2. 找到 .dynsym section                   │                   │
│  │     3. 遍历符号表找 "JNI_OnLoad"              │                   │
│  │     4. 修改 st_value: 0x230C30 → 0x232FB8    │  ← 关键篡改       │
│  └─────────────────────────────────────────────┘                    │
│       ↓                                                             │
│  linker: 在 .dynsym 中查找 "JNI_OnLoad" 符号                         │
│       ↓                                                             │
│  linker: 读到 st_value = 0x232FB8 (已被篡改！)                       │
│       ↓                                                             │
│  linker: 调用 base + 0x232FB8 → sub_232FB8()    ← 假 JNI_OnLoad    │
│       ↓                                                             │
│  sub_232FB8: 解密/反检测/环境检查...                                  │
│       ↓                                                             │
│  sub_232FB8 → sub_12C89C(vm, reserved)          ← 真 JNI_OnLoad    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
收起代码
▼
二、ELF .dynsym 结构回顾
c
// ELF64 Symbol Table Entry (24 bytes)
typedef struct {
Elf64_Word    st_name;    // 符号名在 .dynstr 中的偏移
unsigned char st_info;    // 类型 + 绑定属性
unsigned char st_other;   // 可见性
Elf64_Half    st_shndx;   // 所在 section index
Elf64_Addr    st_value;   // ★ 符号的虚拟地址 (相对基址的偏移)
Elf64_Xword   st_size;    // 符号大小
} Elf64_Sym;
在磁盘上的 .dynsym 中，JNI_OnLoad 的 entry：

plain
原始状态:
┌─────────────────────────────────────────┐
│ st_name  = 0x1234  (→ "JNI_OnLoad")    │
│ st_info  = 0x12    (STB_GLOBAL|STT_FUNC)│
│ st_other = 0x00                          │
│ st_shndx = 0x0E    (.text)              │
│ st_value = 0x230C30 ← 原始真实地址       │
│ st_size  = 0x100                         │
└─────────────────────────────────────────┘

篡改后:
┌─────────────────────────────────────────┐
│ st_name  = 0x1234  (→ "JNI_OnLoad")    │
│ st_info  = 0x12    (不变)               │
│ st_other = 0x00    (不变)               │
│ st_shndx = 0x0E    (不变)               │
│ st_value = 0x232FB8 ← 被修改为 wrapper  │
│ st_size  = 0x100   (不变)               │
└─────────────────────────────────────────┘
三、为什么 .dynsym 在内存中可写？
plain
关键问题：.dynsym 不是只读段吗？

┌─────────────────────────────────────────────────────────────┐
│ ELF Segment (Program Header) 视角：                          │
│                                                             │
│ LOAD segment 1: 文件偏移 0x0000 ~ 0x500000                  │
│   包含: .dynsym, .dynstr, .text, .rodata                    │
│   权限: R-X (只读可执行)                                     │
│                                                             │
│ LOAD segment 2: 文件偏移 0x500000 ~ 0x620000                │
│   包含: .data.rel.ro, .got, .data, .bss                     │
│   权限: RW- (可读写)                                         │
│                                                             │
│ 但是！linker 在做重定位时需要修改内存                          │
│ → linker 会临时 mprotect 某些页为 RW                         │
│ → 或者在某些 Android 版本中，整个 LOAD 段                     │
│   在重定位阶段都是 RW 的                                     │
│                                                             │
│ ★ .init_array 在重定位之后执行                               │
│ ★ 此时 .dynsym 所在页可能已恢复为 R--                        │
│ ★ 所以 sub_232A90 需要先 mprotect 再修改                     │
└─────────────────────────────────────────────────────────────┘
四、sub_232A90 的实现逻辑还原
c
// sub_232A90 的逆向还原 (伪代码)
void sub_232A90() {
// === Step 1: 获取自身 module 基址 ===
// 通过 dl_iterate_phdr 或直接读 /proc/self/maps
// 或者利用已知的相对偏移回算
Elf64_Addr base = get_self_base();

    // === Step 2: 解析 ELF header ===
    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)base;
    Elf64_Phdr* phdr = (Elf64_Phdr*)(base + ehdr->e_phoff);
    
    // === Step 3: 从 PT_DYNAMIC 段获取 .dynsym 和 .dynstr ===
    Elf64_Sym*  dynsym  = NULL;
    char*       dynstr  = NULL;
    uint64_t    sym_cnt = 0;
    
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            Elf64_Dyn* dyn = (Elf64_Dyn*)(base + phdr[i].p_vaddr);
            
            while (dyn->d_tag != DT_NULL) {
                switch (dyn->d_tag) {
                    case DT_SYMTAB:   // 6
                        dynsym = (Elf64_Sym*)(base + dyn->d_un.d_ptr);
                        break;
                    case DT_STRTAB:   // 5
                        dynstr = (char*)(base + dyn->d_un.d_ptr);
                        break;
                    case DT_HASH:     // 4 — 用 hash table 获取符号数量
                    case DT_GNU_HASH: // 0x6ffffef5
                        // 从 hash table 获取 nsyms
                        sym_cnt = get_nsyms_from_hash(base + dyn->d_un.d_ptr);
                        break;
                }
                dyn++;
            }
            break;
        }
    }
    
    // === Step 4: 遍历 .dynsym 搜索 "JNI_OnLoad" ===
    for (uint64_t i = 0; i < sym_cnt; i++) {
        const char* name = dynstr + dynsym[i].st_name;
        
        if (strcmp(name, "JNI_OnLoad") == 0) {
            
            // === Step 5: mprotect 使 .dynsym 所在页可写 ===
            uintptr_t page = (uintptr_t)&dynsym[i].st_value & ~0xFFF;
            mprotect((void*)page, 0x1000, PROT_READ | PROT_WRITE);
            
            // === Step 6: 篡改 st_value ===
            // 原始: 0x230C30 (真正的 JNI_OnLoad)
            // 修改为: 0x232FB8 (wrapper/检测函数)
            dynsym[i].st_value = 0x232FB8;  // sub_232FB8
            
            // === Step 7: (可选) 恢复权限 ===
            mprotect((void*)page, 0x1000, PROT_READ);
            
            // === Step 8: (可选) 清除 cache ===
            __builtin___clear_cache((void*)page, (void*)(page + 0x1000));
            
            break;
        }
    }
}
收起代码
▼
五、为什么这个时机有效？
plain
┌─────────────────────────────────────────────────────────────────┐
│  Android Linker 调用 JNI_OnLoad 的源码 (简化)                     │
│                                                                 │
│  // art/runtime/java_vm_ext.cc                                  │
│  bool JavaVMExt::LoadNativeLibrary(...) {                       │
│      ...                                                        │
│      // dlopen 完成后（此时 init_array 已经执行完毕）              │
│      void* handle = android_dlopen_ext(path, ...);              │
│                                                                 │
│      // ★ 通过 dlsym 查找 JNI_OnLoad                            │
│      // dlsym 会读取 .dynsym 中的 st_value                       │
│      void* sym = dlsym(handle, "JNI_OnLoad");                   │
│                                                                 │
│      if (sym != nullptr) {                                      │
│          // 此时读到的已经是被篡改后的地址！                       │
│          JNI_OnLoadFn jni_on_load = (JNI_OnLoadFn)sym;          │
│          int version = jni_on_load(vm, nullptr);  // → 0x232FB8│
│      }                                                          │
│  }                                                              │
└─────────────────────────────────────────────────────────────────┘

时间线：
────────────────────────────────────────────────────────────────────
t1          t2              t3           t4          t5
│           │               │            │           │
▼           ▼               ▼            ▼           ▼
mmap       重定位          init_array    dlsym      调用
加载ELF    GOT/PLT填充     执行          查找符号    JNI_OnLoad
│
├→ sub_2327C8()
├→ sub_232A90()
└→ 篡改 .dynsym ★
│
▼
读到篡改后的
st_value !!!
────────────────────────────────────────────────────────────────────
收起代码
▼
六、sub_232FB8 (假 JNI_OnLoad) 的典型逻辑
c
// sub_232FB8: 伪装的 JNI_OnLoad
jint sub_232FB8(JavaVM* vm, void* reserved) {

    // === 阶段 1: 环境检测 ===
    if (detect_frida()) {
        // 退出/崩溃/返回假数据
        return -1;
    }
    
    if (detect_debugger()) {
        return -1;
    }
    
    if (detect_root()) {
        // 设置全局标志
        g_is_rooted = 1;
    }
    
    // === 阶段 2: 解密/解混淆 ===
    decrypt_strings();
    unpack_code_section();
    
    // === 阶段 3: Hook 自身的关键函数 (内联 hook) ===
    install_integrity_checks();
    
    // === 阶段 4: 调用真正的 JNI_OnLoad ===
    // 0x12C89C 才是真正注册 JNI 方法的地方
    return sub_12C89C(vm, reserved);  // 真正的 JNI_OnLoad
}
收起代码
▼
c
// sub_12C89C: 真正的 JNI_OnLoad
jint sub_12C89C(JavaVM* vm, void* reserved) {
JNIEnv* env;
vm->GetEnv((void**)&env, JNI_VERSION_1_6);

    // 注册 native methods
    JNINativeMethod methods[] = {
        {"nativeInit", "(I)V", (void*)native_init_impl},
        {"nativeProcess", "([B)[B", (void*)native_process_impl},
        // ...
    };
    
    jclass cls = env->FindClass("com/example/NativeLib");
    env->RegisterNatives(cls, methods, sizeof(methods)/sizeof(methods[0]));
    
    return JNI_VERSION_1_6;
}
七、这种技术的目的
plain
┌──────────────────────────────────────────────────────────────┐
│  为什么要这样做？而不是直接在 JNI_OnLoad 里写检测代码？        │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  1. 【反静态分析】                                            │
│     - IDA 中 JNI_OnLoad 指向 0x230C30 (无害的注册代码)        │
│     - 分析者不会注意到真正的入口是 0x232FB8                    │
│     - 静态交叉引用分析会误导分析方向                           │
│                                                              │
│  2. 【反 Hook】                                              │
│     - 如果攻击者 hook JNI_OnLoad(0x230C30)                   │
│     - 实际执行的是 0x232FB8，hook 无效！                      │
│       (因为 linker 读取的是修改后的地址)                       │
│                                                              │
│  3. 【执行时序控制】                                          │
│     - init_array 先于 JNI_OnLoad 执行                        │
│     - 可以在 init_array 中完成环境准备                        │
│     - wrapper 中再做最后的运行时检查                           │
│                                                              │
│  4. 【灵活路由】                                              │
│     - 可根据检测结果动态决定跳转到哪个函数                     │
│     - 正常环境 → 真实 JNI_OnLoad                             │
│     - 异常环境 → 假的/空的 JNI_OnLoad (或直接 abort)          │
│                                                              │
└──────────────────────────────────────────────────────────────┘
