package com.demo.jnionload

import android.util.Log

/**
 * JNI_OnLoad .dynsym 篡改技术方案 — Java/Kotlin 入口
 *
 * 调用 [init] 方法加载 libjnionload.so，触发整个保护机制。
 *
 * 加载流程：
 *   1. System.loadLibrary("jnionload")
 *   2. linker 加载 .so，执行 .init_array 中的 init_patch_dynsym()
 *   3. init_patch_dynsym() 篡改 .dynsym 中 JNI_OnLoad 的 st_value
 *   4. linker 通过 dlsym 查找 JNI_OnLoad → 返回 fake_JNI_OnLoad
 *   5. fake_JNI_OnLoad 执行反检测逻辑后调用 real_JNI_OnLoad
 */
object JniOnLoadLibrary {

    private const val TAG = "JniOnLoadLibrary"
    private var isLoaded = false

    /**
     * 加载 native library 并触发 JNI_OnLoad 篡改保护
     *
     * 建议在 Application.onCreate() 或 MainActivity 中尽早调用。
     * 越早加载，保护窗口越早建立。
     *
     * @throws UnsatisfiedLinkError 如果 library 加载失败
     */
    @Synchronized
    fun init() {
        if (isLoaded) {
            Log.w(TAG, "Library already loaded, skipping")
            return
        }

        Log.i(TAG, "============================================")
        Log.i(TAG, "Loading libjnionload.so...")
        Log.i(TAG, "This will trigger the .dynsym JNI_OnLoad patch")
        Log.i(TAG, "============================================")

        try {
            System.loadLibrary("jnionload")
            isLoaded = true
            Log.i(TAG, "libjnionload.so loaded successfully")
            Log.i(TAG, "Check logcat for 'JniOnLoadTamper' to verify patch status")
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "Failed to load libjnionload.so", e)
            throw e
        }
    }

    /**
     * 检查 library 是否已加载
     */
    fun isInitialized(): Boolean = isLoaded
}
