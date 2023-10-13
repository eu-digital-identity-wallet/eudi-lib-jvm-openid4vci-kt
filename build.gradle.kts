object Meta {
    const val ORG_URL = "https://github.com/eu-digital-identity-wallet"
    const val PROJ_DESCR = "OpenId4VCI wallet role library"
    const val PROJ_BASE_DIR = "https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-openid4vci-kt"
    const val PROJ_GIT_URL = "scm:git:git@github.com:eu-digital-identity-wallet/eudi-lib-jvm-openid4vci-kt.git"
    const val PROJ_SSH_URL = "scm:git:ssh://github.com:eu-digital-identity-wallet/eudi-lib-jvm-openid4vci-kt.git"
}

plugins {
    alias(libs.plugins.dependency.check)
    alias(libs.plugins.sonarqube)
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.spotless)
    `java-library`
    `maven-publish`
    signing
    jacoco
}

extra["isReleaseVersion"] = !version.toString().endsWith("SNAPSHOT")

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
    api(libs.ktor.serialization.kotlinx.cbor)
    testImplementation(libs.jsoup)
    testImplementation(kotlin("test"))
    testImplementation(libs.ktor.client.okhttp)
    testImplementation(libs.ktor.server.test.host)
    testImplementation(libs.ktor.server.content.negotiation)
    testImplementation(libs.ktor.client.mock)
    testImplementation(libs.cbor)
}

java {
    sourceCompatibility = JavaVersion.toVersion(libs.versions.java.get())

    withSourcesJar()
    withJavadocJar()
}

kotlin {
    jvmToolchain {
        languageVersion.set(JavaLanguageVersion.of(libs.versions.java.get()))
        vendor.set(JvmVendorSpec.ADOPTIUM)
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

tasks.jacocoTestReport {
    reports {
        xml.required.set(true)
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

publishing {
    publications {
        create<MavenPublication>("library") {
            from(components["java"])
            pom {
                name.set(project.name)
                description.set(Meta.PROJ_DESCR)
                url.set(Meta.PROJ_BASE_DIR)
                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                scm {
                    connection.set(Meta.PROJ_GIT_URL)
                    developerConnection.set(Meta.PROJ_SSH_URL)
                    url.set(Meta.PROJ_BASE_DIR)
                }
                issueManagement {
                    system.set("github")
                    url.set(Meta.PROJ_BASE_DIR + "/issues")
                }
                ciManagement {
                    system.set("github")
                    url.set(Meta.PROJ_BASE_DIR + "/actions")
                }
                developers {
                    organization {
                        url.set(Meta.ORG_URL)
                    }
                }
            }
        }
    }
    repositories {

        val sonaUri =
            if ((extra["isReleaseVersion"]) as Boolean) {
                "https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/"
            } else {
                "https://s01.oss.sonatype.org/content/repositories/snapshots/"
            }

        maven {
            name = "sonatype"
            url = uri(sonaUri)
            credentials(PasswordCredentials::class)
        }
    }
}

signing {
    setRequired({
        (project.extra["isReleaseVersion"] as Boolean) && gradle.taskGraph.hasTask("publish")
    })
    val signingKeyId: String? by project
    val signingKey: String? by project
    val signingPassword: String? by project
    useInMemoryPgpKeys(signingKeyId, signingKey, signingPassword)
    sign(publishing.publications["library"])
}
