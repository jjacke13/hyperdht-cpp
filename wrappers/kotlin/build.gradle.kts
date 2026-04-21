plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.hyperdht"
    compileSdk = 34

    defaultConfig {
        minSdk = 26
        ndk { abiFilters += listOf("arm64-v8a") }
        externalNativeBuild {
            cmake { arguments("-DANDROID_STL=c++_shared") }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("CMakeLists.txt")
            version = "3.22.1"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
}
