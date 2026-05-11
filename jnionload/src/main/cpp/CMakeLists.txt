cmake_minimum_required(VERSION 3.22.1)
project("jnionload")

# Enable hidden visibility for all symbols by default
# Only JNI_OnLoad will be explicitly exported
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

add_library(
    jnionload
    SHARED
    jni_onload_tamper.c
)

target_compile_options(jnionload PRIVATE
    -Wall
    -Wextra
    -O2
    -fvisibility=hidden
)

# Link against log library for __android_log_print
target_link_libraries(jnionload
    PRIVATE
    log
    dl
)
