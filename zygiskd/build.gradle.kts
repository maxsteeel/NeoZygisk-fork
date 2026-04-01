plugins {
    id("com.android.library")
}

val defaultCFlags = arrayOf(
    "-Wall", "-Wextra",
    "-fno-rtti", "-fno-exceptions",
    "-fno-stack-protector", "-fomit-frame-pointer",
    "-ffunction-sections", "-fdata-sections",
    "-fno-ident", "-fmerge-all-constants",
    "-fno-semantic-interposition",
    "-Wno-builtin-macro-redefined", "-D__FILE__=__FILE_NAME__",
)

val releaseFlags = arrayOf(
    "-Oz", "-flto", "-g0", "-fno-math-errno",
    "-fno-use-cxa-atexit", "-fno-threadsafe-statics", "-fno-unroll-loops", 
    "-falign-functions=1", "-fno-jump-tables", "-fno-c++-static-destructors",
    "-fno-keep-static-consts", "-fno-keep-persistent-storage-variables",
    "-fno-register-global-dtors-with-atexit", "-fwhole-program-vtables",
    "-fno-common", "-fno-verbose-asm", "-fvirtual-function-elimination",
    "-Wno-unused", "-Wno-unused-parameter",
    "-fvisibility=hidden", "-fvisibility-inlines-hidden",
    "-fno-unwind-tables", "-fno-asynchronous-unwind-tables"
)

val linkerFlags = arrayOf(
    "-unwindlib=none", "-Wl,--no-rosegment",
    "-Wl,--discard-all", "-Wl,--no-eh-frame-hdr",
    "-Wl,--exclude-libs,ALL", "-Wl,--gc-sections", 
    "-Wl,--strip-all", "-Wl,-z,norelro",
    "-Wl,--build-id=none", "-Wl,-s",
    "-Wl,--icf=all", "-Wl,--as-needed",
    "-Wl,-Bsymbolic", "-Wl,--hash-style=gnu",
)

android {
    ndkVersion = rootProject.extra["androidCompileNdkVersion"] as String

    defaultConfig {
        externalNativeBuild {
            cmake {
                cFlags("-std=c18", *defaultCFlags)
		        cppFlags("-std=c++23", *defaultCFlags)
                arguments(
                    "-DZKSU_VERSION=\"${rootProject.extra["verName"]}\"",
                    "-DMIN_APATCH_VERSION=${rootProject.extra["minAPatchVersion"]}",
                    "-DMIN_KSU_VERSION=${rootProject.extra["minKsuVersion"]}",
                    "-DMAX_KSU_VERSION=${rootProject.extra["maxKsuVersion"]}",
                    "-DMIN_MAGISK_VERSION=${rootProject.extra["minMagiskVersion"]}",
                    "-DCMAKE_SHARED_LINKER_FLAGS=-Wl,--entry=main",
                    "-DCMAKE_EXE_LINKER_FLAGS=-Wl,--entry=main"
                )
                abiFilters("armeabi-v7a", "arm64-v8a", "x86", "x86_64")
            }
        }
    }

    externalNativeBuild.cmake { path("src/CMakeLists.txt") }

    buildTypes {
        release {
            externalNativeBuild.cmake {
                cFlags += releaseFlags
                cppFlags += releaseFlags
                arguments += "-DCMAKE_SHARED_LINKER_FLAGS=${linkerFlags.joinToString(" ")}"
                arguments += "-DCMAKE_EXE_LINKER_FLAGS=${linkerFlags.joinToString(" ")}"
            }
        }
    }
}
