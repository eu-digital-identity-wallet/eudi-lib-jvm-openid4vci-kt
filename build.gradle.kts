import org.jetbrains.dokka.DokkaConfiguration
import org.jetbrains.dokka.gradle.DokkaTask
import org.jetbrains.kotlin.gradle.dsl.KotlinVersion
import org.owasp.dependencycheck.gradle.extension.DependencyCheckExtension
import java.net.URI

object Meta {
    const val BASE_URL = "https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-openid4vci-kt"
}

plugins {
    base
    `java-library`
    alias(libs.plugins.dokka)
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.spotless)
    alias(libs.plugins.kover)
    alias(libs.plugins.dependency.check)
    alias(libs.plugins.maven.publish)
}

repositories {
    mavenCentral()
    mavenLocal()
    maven {
        url = uri("https://s01.oss.sonatype.org/content/repositories/snapshots/")
        mavenContent { snapshotsOnly() }
    }
}

dependencies {
    api(libs.nimbus.oauth2.oidc.sdk)
    api(libs.ktor.client.core)
    api(libs.ktor.client.content.negotiation)
    api(libs.ktor.client.serialization)
    api(libs.ktor.serialization.kotlinx.json)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.jsoup)
    testImplementation(kotlin("test"))
    testImplementation(libs.ktor.client.okhttp)
    testImplementation(libs.ktor.server.test.host)
    testImplementation(libs.ktor.server.content.negotiation)
    testImplementation(libs.ktor.client.mock)
    testImplementation(libs.ktor.client.logging)
    testImplementation(libs.logback.classic)
    testImplementation(libs.cbor)
    testImplementation(libs.tink)
}

java {
    sourceCompatibility = JavaVersion.toVersion(libs.versions.java.get())
}

kotlin {
    jvmToolchain {
        languageVersion = JavaLanguageVersion.of(libs.versions.java.get())
        vendor = JvmVendorSpec.ADOPTIUM
    }
    compilerOptions {
        apiVersion = KotlinVersion.KOTLIN_2_1
    }
}

spotless {
    kotlin {
        ktlint(libs.versions.ktlint.get())
        licenseHeaderFile("FileHeader.txt")
    }
    kotlinGradle {
        ktlint(libs.versions.ktlint.get())
    }
}

testing {
    suites {
        val test by getting(JvmTestSuite::class) {
            useJUnitJupiter()
        }
    }
}

tasks.jar {
    manifest {
        attributes(
            mapOf(
                "Implementation-Title" to project.name,
                "Implementation-Version" to project.version,
            ),
        )
    }
}

tasks.withType<DokkaTask>().configureEach {
    dokkaSourceSets {
        named("main") {
            // used as project name in the header
            moduleName.set("EUDI OpenId4VCI library")

            // contains descriptions for the module and the packages
            includes.from("Module.md")

            documentedVisibilities.set(setOf(DokkaConfiguration.Visibility.PUBLIC, DokkaConfiguration.Visibility.PROTECTED))

            val remoteSourceUrl = System.getenv()["GIT_REF_NAME"]?.let { URI.create("${Meta.BASE_URL}/tree/$it/src").toURL() }
            remoteSourceUrl
                ?.let {
                    sourceLink {
                        localDirectory.set(projectDir.resolve("src"))
                        remoteUrl.set(it)
                        remoteLineSuffix.set("#L")
                    }
                }
        }
    }
}

mavenPublishing {
    pom {
        ciManagement {
            system = "github"
            url = "${Meta.BASE_URL}/actions"
        }
    }
}

val nvdApiKey: String? = System.getenv("NVD_API_KEY") ?: properties["nvdApiKey"]?.toString()
val dependencyCheckExtension = extensions.findByType(DependencyCheckExtension::class.java)
dependencyCheckExtension?.apply {
    formats = mutableListOf("XML", "HTML")
    nvd.apiKey = nvdApiKey ?: ""
}
