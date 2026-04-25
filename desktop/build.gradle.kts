import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

repositories {
    google()
    mavenCentral()
    maven("https://central.sonatype.com/repository/maven-snapshots")
}

plugins {
    id("org.jetbrains.kotlin.jvm")
    id("org.jetbrains.compose") version Version.compose
    id("org.jetbrains.kotlin.plugin.compose") version Version.kotlin
}

val buildType by properties
val specifics by properties
val platform by properties
val arch by properties

sourceSets {
    getByName("main") {
        kotlin.srcDirs("../shared/src/$name/kotlin")
        setOf(buildType, specifics).forEach { name ->
            kotlin.srcDirs("src/$name/kotlin")
            kotlin.srcDirs("../shared/src/$name/kotlin")
        }
    }
}

tasks.getByName<JavaCompile>("compileJava") {
    targetCompatibility = Version.jvmTarget
}

tasks.getByName<KotlinCompile>("compileKotlin") {
    compilerOptions.jvmTarget = JvmTarget.fromTarget(Version.jvmTarget)
}

compose.desktop {
    application {
        mainClass = "test.cmp.messages.AppKt"
    }
}

dependencies {
    when (val entry = Pair(platform, arch)) {
        "macos" to "arm64" -> {
            implementation(compose.desktop.macos_arm64)
        }
        else -> error("Platform \"${entry.first}(${entry.second})\" is not supported!")
    }
    implementation("com.github.kepocnhh:Bytes:0.4.2u-SNAPSHOT")
    implementation("com.github.kepocnhh:Hashes:0.2.1-SNAPSHOT")
    implementation("com.github.kepocnhh:Logics:0.2.0")
    implementation("com.github.kepocnhh:Secrets:0.3.2-SNAPSHOT")
    implementation("com.squareup.okhttp3:okhttp:5.3.0")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.82")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-swing:1.8.1")
}
