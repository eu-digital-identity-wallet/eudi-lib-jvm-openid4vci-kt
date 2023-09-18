object Meta {
    const val ORG_URL = "https://github.com/eu-digital-identity-wallet"
    const val PROJ_DESCR = "OpenId4VCI wallet role library"
    const val PROJ_BASE_DIR = "https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-openid4vci-kt"
    const val PROJ_GIT_URL = "scm:git:git@github.com:eu-digital-identity-wallet/eudi-lib-jvm-openid4vci-kt.git"
    const val PROJ_SSH_URL = "scm:git:ssh://github.com:eu-digital-identity-wallet/eudi-lib-jvm-openid4vci-kt.git"
}

plugins {
    id("org.owasp.dependencycheck") version "8.4.0"
    id("org.sonarqube") version "4.3.0.3225"
    kotlin("jvm") version "1.8.21"
    kotlin("plugin.serialization") version "1.8.21"
    id("com.diffplug.spotless") version "6.20.0"
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

val ktorVersion = "2.3.3"

val nimbusSdkVersion = "10.15"

dependencies {
    api("com.nimbusds:oauth2-oidc-sdk:$nimbusSdkVersion")
    api("io.ktor:ktor-client-core:$ktorVersion")
    api("io.ktor:ktor-client-content-negotiation:$ktorVersion")
    api("io.ktor:ktor-client-serialization:$ktorVersion")
    api("io.ktor:ktor-serialization-kotlinx-json:$ktorVersion")
    api("io.ktor:ktor-serialization-kotlinx-cbor:$ktorVersion")
    testImplementation(kotlin("test"))
    testImplementation("io.ktor:ktor-client-okhttp:$ktorVersion")
    testImplementation("io.ktor:ktor-server-test-host:$ktorVersion")
    testImplementation("io.ktor:ktor-server-content-negotiation:$ktorVersion")
    testImplementation("co.nstant.in:cbor:0.9")
}

java {
    withSourcesJar()
    withJavadocJar()
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

testing {
    suites {
        val test by getting(JvmTestSuite::class) {
            useJUnitJupiter()
        }
    }
}

kotlin {
    jvmToolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
        vendor.set(JvmVendorSpec.ADOPTIUM)
    }
    jvmToolchain(11)
}

tasks.jacocoTestReport {
    reports {
        xml.required.set(true)
    }
}

val ktlintVersion = "0.50.0"
spotless {
    kotlin {
        ktlint(ktlintVersion)
        licenseHeaderFile("FileHeader.txt")
    }
    kotlinGradle {
        ktlint(ktlintVersion)
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
