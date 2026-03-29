import android.databinding.tool.ext.capitalizeUS
import java.security.MessageDigest
import org.apache.tools.ant.filters.ReplaceTokens
import org.apache.tools.ant.filters.FixCrLfFilter
import org.apache.commons.codec.binary.Hex

plugins {
    alias(libs.plugins.agp.lib)
}

val moduleId: String by rootProject.extra
val moduleName: String by rootProject.extra
val verCode: Int by rootProject.extra
val verName: String by rootProject.extra
val minAPatchVersion: Int by rootProject.extra
val minKsuVersion: Int by rootProject.extra
val minKsudVersion: Int by rootProject.extra
val maxKsuVersion: Int by rootProject.extra
val minMagiskVersion: Int by rootProject.extra
val workDirectory: String by rootProject.extra
val commitHash: String by rootProject.extra
val updateJson: String by rootProject.extra

android {
    buildFeatures { buildConfig = false }
    androidResources.enable = false
}

androidComponents.onVariants { variant ->
    val variantLowered = variant.name.lowercase()
    val variantCapped = variant.name.capitalizeUS()
    val buildTypeLowered = variant.buildType?.lowercase()

    val moduleDir = layout.buildDirectory.dir("outputs/module/$variantLowered")
    val zipFileName = "$moduleName-$verName-$verCode-$commitHash-$buildTypeLowered.zip".replace(' ', '-')

    val prepareModuleFilesTask = tasks.register<Sync>("prepareModuleFiles$variantCapped") {
        group = "module"
        dependsOn(
            ":loader:assemble$variantCapped",
            ":zygiskd:assemble$variantCapped", 
        )
        into(moduleDir)
        from("${rootProject.projectDir}/README.md")
        from("$projectDir/src") {
            exclude("module.prop", "action.sh", "customize.sh", "post-fs-data.sh", "service.sh", "uninstall.sh", "zygisk-ctl.sh")
            filter<FixCrLfFilter>("eol" to FixCrLfFilter.CrLf.newInstance("lf"))
        }
        from("$projectDir/src") {
            include("module.prop")
            expand(
                "moduleId" to moduleId,
                "moduleName" to moduleName,
                "versionName" to "$verName ($verCode-$commitHash-$variantLowered)",
                "versionCode" to verCode,
                "updateJson" to updateJson
            )
        }
        from("$projectDir/src") {
            include("action.sh", "customize.sh", "post-fs-data.sh", "service.sh", "uninstall.sh", "zygisk-ctl.sh")
            val tokens = mapOf(
                "DEBUG" to if (buildTypeLowered == "debug") "true" else "false",
                "MIN_APATCH_VERSION" to "$minAPatchVersion",
                "MIN_KSU_VERSION" to "$minKsuVersion",
                "MIN_KSUD_VERSION" to "$minKsudVersion",
                "MAX_KSU_VERSION" to "$maxKsuVersion",
                "MIN_MAGISK_VERSION" to "$minMagiskVersion",
                "WORK_DIRECTORY" to "$workDirectory",
            )
            filter<ReplaceTokens>("tokens" to tokens)
            filter<FixCrLfFilter>("eol" to FixCrLfFilter.CrLf.newInstance("lf"))
        }
        into("bin") {
            from(project(":zygiskd").layout.buildDirectory.dir("out"))
            include("**/zygiskd")
        }
        into("lib") {
            from(project(":loader").layout.buildDirectory.dir("out"))
        }

        doLast {
            fileTree(moduleDir).visit {
                if (isDirectory) return@visit
                val md = MessageDigest.getInstance("SHA-256")
                file.forEachBlock(4096) { bytes, size -> md.update(bytes, 0, size) }
                file(file.path + ".sha256").writeText(Hex.encodeHexString(md.digest()))
            }
        }
    }

    val zipTask = tasks.register<Zip>("zip$variantCapped") {
        group = "module"
        dependsOn(prepareModuleFilesTask)
        archiveFileName.set(zipFileName)
        destinationDirectory.set(layout.buildDirectory.dir("outputs/release").get().asFile)
        from(moduleDir)
    }

    val pushTask = tasks.register<Exec>("push$variantCapped") {
        group = "module"
        dependsOn(zipTask)
        commandLine("adb", "push", zipTask.get().outputs.files.singleFile.path, "/data/local/tmp")
    }

    val installAPatchTask = tasks.register("installAPatch$variantCapped") {
        group = "module"
        dependsOn(pushTask)
        doLast {
            providers.exec { commandLine("adb", "shell", "echo", "/data/adb/apd module install /data/local/tmp/$zipFileName", "> /data/local/tmp/install.sh") }.result.get()
            providers.exec { commandLine("adb", "shell", "chmod", "755", "/data/local/tmp/install.sh") }.result.get()
            providers.exec { commandLine("adb", "shell", "su", "-c", "/data/local/tmp/install.sh") }.result.get()
        }
    }

    val installKsuTask = tasks.register("installKsu$variantCapped") {
        group = "module"
        dependsOn(pushTask)
        doLast {
            providers.exec { commandLine("adb", "shell", "echo", "/data/adb/ksud module install /data/local/tmp/$zipFileName", "> /data/local/tmp/install.sh") }.result.get()
            providers.exec { commandLine("adb", "shell", "chmod", "755", "/data/local/tmp/install.sh") }.result.get()
            providers.exec { commandLine("adb", "shell", "su", "-c", "/data/local/tmp/install.sh") }.result.get()
        }
    }

    val installMagiskTask = tasks.register<Exec>("installMagisk$variantCapped") {
        group = "module"
        dependsOn(pushTask)
        commandLine("adb", "shell", "su", "-M", "-c", "magisk --install-module /data/local/tmp/$zipFileName")
    }

    tasks.register<Exec>("installAPatchAndReboot$variantCapped") { group = "module"; dependsOn(installAPatchTask); commandLine("adb", "reboot") }
    tasks.register<Exec>("installKsuAndReboot$variantCapped") { group = "module"; dependsOn(installKsuTask); commandLine("adb", "reboot") }
    tasks.register<Exec>("installMagiskAndReboot$variantCapped") { group = "module"; dependsOn(installMagiskTask); commandLine("adb", "reboot") }
}
