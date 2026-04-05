import java.nio.file.Paths
import org.gradle.internal.os.OperatingSystem

plugins {
    alias(libs.plugins.agp.lib)
}

val verCode: Int by rootProject.extra
val verName: String by rootProject.extra
val commitHash: String by rootProject.extra
val workDirectory: String by rootProject.extra

fun Project.findInPath(executable: String, property: String): String? {
    val pathEnv = System.getenv("PATH")
    return pathEnv.split(File.pathSeparator).map { folder ->
        Paths.get("${folder}${File.separator}${executable}${if (OperatingSystem.current().isWindows) ".exe" else ""}")
            .toFile()
    }.firstOrNull { path ->
        path.exists()
    }?.absolutePath ?: properties.getOrDefault(property, null) as? String?
}

val ccachePath by lazy {
    project.findInPath("ccache", "ccache.path")?.also {
        println("loader: Use ccache: $it")
    }
}

val defaultCFlags = arrayOf(
    "-Wall", "-Wextra",
    "-fno-rtti", "-fno-exceptions",
    "-fno-stack-protector", "-fomit-frame-pointer",
    "-ffunction-sections", "-fdata-sections",
    "-fno-ident", "-fmerge-all-constants",
    "-fno-semantic-interposition",
    "-Wno-builtin-macro-redefined", "-D__FILE__=__FILE_NAME__",
    "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0",
    "-DWORK_DIRECTORY='\"${workDirectory}\"'"
)

val releaseFlags = arrayOf(
    "-Oz", "-flto", "-fno-math-errno",
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
    "-Wl,--build-id=none", "-Wl,-s", "-fno-plt",
    "-Wl,--icf=all", "-Wl,--as-needed",
    "-Wl,-Bsymbolic", "-Wl,--hash-style=gnu"
)

android {
    buildFeatures {
        android.androidResources.enable = false
        buildConfig = false
        prefab = true
    }

    externalNativeBuild.cmake {
        path("src/CMakeLists.txt")
        buildStagingDirectory = layout.buildDirectory.get().asFile
    }

    defaultConfig {
        externalNativeBuild.cmake {
            cFlags("-std=c18", *defaultCFlags)
            cppFlags("-std=c++20", *defaultCFlags)
            ccachePath?.let {
                arguments(
                    "-DCMAKE_C_COMPILER_LAUNCHER=$it",
                    "-DCMAKE_CXX_COMPILER_LAUNCHER=$it"
                )
            }
        }
    }

    buildTypes {
        debug {
            externalNativeBuild.cmake {
                arguments += "-DZKSU_VERSION=$verName-$verCode-$commitHash-debug"
            }
        }
        release {
            externalNativeBuild.cmake {
                cFlags += releaseFlags
                cppFlags += releaseFlags
                arguments += "-DCMAKE_SHARED_LINKER_FLAGS=${linkerFlags.joinToString(" ")}"
                arguments += "-DCMAKE_EXE_LINKER_FLAGS=${linkerFlags.joinToString(" ")}"
                arguments += "-DZKSU_VERSION=$verName-$verCode-$commitHash-release"
            }
        }
    }
}
