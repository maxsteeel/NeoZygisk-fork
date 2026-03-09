plugins {
    alias(libs.plugins.agp.lib)
    alias(libs.plugins.rust.android)
}

val minAPatchVersion: Int by rootProject.extra
val minKsuVersion: Int by rootProject.extra
val maxKsuVersion: Int by rootProject.extra
val minMagiskVersion: Int by rootProject.extra
val verCode: Int by rootProject.extra
val verName: String by rootProject.extra
val commitHash: String by rootProject.extra

android {
    buildFeatures {
        buildConfig = false
    }
    androidResources.enable = false
}

cargo {
    module = "."
    libname = "zygiskd"
    targetIncludes = arrayOf("zygiskd")
    targets = listOf("arm64", "arm", "x86", "x86_64")
    targetDirectory = "build/intermediates/rust"
    val isDebug = gradle.startParameter.taskNames.any { it.lowercase().contains("debug") }
    profile = if (isDebug) "debug" else "release"
    exec = { spec, _ ->
        spec.environment("ANDROID_NDK_HOME", android.ndkDirectory.path)
        spec.environment("MIN_APATCH_VERSION", minAPatchVersion)
        spec.environment("MIN_KSU_VERSION", minKsuVersion)
        spec.environment("MAX_KSU_VERSION", maxKsuVersion)
        spec.environment("MIN_MAGISK_VERSION", minMagiskVersion)
        spec.environment("ZKSU_VERSION", "$verName-$verCode-$commitHash-$profile")
    }
}

afterEvaluate {
    tasks.register("buildAndStrip") {
        dependsOn(":zygiskd:cargoBuild")
        val isDebug = gradle.startParameter.taskNames.any { it.lowercase().contains("debug") }
        doLast {
            val dir = layout.buildDirectory.dir("rustJniLibs/android").get().asFile
            val prebuilt = File(android.ndkDirectory, "toolchains/llvm/prebuilt").listFiles()!!.first()
            val binDir = File(prebuilt, "bin")
            val symbolDir = layout.buildDirectory.dir("symbols/${if (isDebug) "debug" else "release"}").get().asFile
            symbolDir.mkdirs()
            val suffix = if (prebuilt.name.contains("windows")) ".exe" else ""
            val strip = File(binDir, "llvm-strip$suffix")
            val objcopy = File(binDir, "llvm-objcopy$suffix")
            dir.listFiles()!!.forEach {
                if (!it.isDirectory) return@forEach
                val symbolPath = File(symbolDir, "${it.name}/zygiskd.debug")
                symbolPath.parentFile.mkdirs()
                providers.exec {
                    workingDir = it
                    commandLine(objcopy, "--only-keep-debug", "zygiskd", symbolPath)
                }.result.get()
                providers.exec {
                    workingDir = it
                    commandLine(strip, "--strip-all", "zygiskd")
                }.result.get()
                providers.exec {
                    workingDir = it
                    commandLine(objcopy, "--add-gnu-debuglink", symbolPath, "zygiskd")
                }.result.get()
            }
        }
    }
}
