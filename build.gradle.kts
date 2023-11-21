plugins {
    kotlin("jvm") version "1.9.20"
}

group = "org.lnwSchnorr"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(kotlin("test"))

    testImplementation("org.junit.platform:junit-platform-console-standalone:1.9.2")
}

tasks.test {
    useJUnitPlatform()
}

tasks {

    compileTestKotlin {
        kotlinOptions {
            jvmTarget = "17"
        }
    }

    compileKotlin {
        kotlinOptions {
            jvmTarget = "17"
        }
    }

}

kotlin {

    sourceSets.all {
        languageSettings {
            version = 2.0
        }
    }
}