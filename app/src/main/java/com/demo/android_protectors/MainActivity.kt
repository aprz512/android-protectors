package com.demo.android_protectors

import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import com.demo.jnionload.JniOnLoadLibrary

class MainActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "MainActivity"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        Log.i(TAG, "MainActivity created — initializing JNI_OnLoad protector...")

        // 加载 libjnionload.so，触发 .dynsym JNI_OnLoad 篡改
        // 在 logcat 中过滤 "JniOnLoadTamper" 观察完整的 patch 过程
        JniOnLoadLibrary.init()

        Log.i(TAG, "JNI_OnLoad protector initialized: ${JniOnLoadLibrary.isInitialized()}")
    }
}
