plugins {
    kotlin("multiplatform") version "1.3.70"
}

repositories {
    mavenCentral()
    //jcenter()
    maven("https://dl.bintray.com/korlibs/korlibs")
}

kotlin {
    linuxX64("android") {
        binaries {
            executable {
                entryPoint = "org.evolution.ota.main"
                this.linkerOpts("-static")
            }
        }
    }

    sourceSets {
        val androidMain by getting {
            dependencies {
                implementation("com.soywiz.korlibs.krypto:krypto-linuxx64:1.10.0")
                implementation("com.soywiz.korlibs.krypto:krypto:1.10.0")
            }
        }
    }
}