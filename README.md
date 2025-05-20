
# 🔐 Android NDK Security Toolkit

![Android](https://img.shields.io/badge/Android-3DDC84?style=for-the-badge&logo=android&logoColor=white)
![NDK](https://img.shields.io/badge/NDK-00C4CC?style=for-the-badge&logo=android&logoColor=white)
![C++](https://img.shields.io/badge/C++-00599C?style=for-the-badge&logo=c%2B%2B&logoColor=white)
[![Download](https://img.shields.io/badge/Download-Zip-blue?style=for-the-badge&logo=github)](https://github.com/yourusername/android-ndk-security-toolkit/archive/refs/heads/main.zip)

A robust native security layer for Android apps that protects against reverse engineering, tampering, and runtime attacks using C++ and the Native Development Kit (NDK).

---

## ✨ Features

- **XOR Encryption** for sensitive strings (API keys, URLs)
- **Signature Verification** to prevent APK tampering
- **Runtime Protection** against:
  - Debuggers (`ptrace` detection)
  - Frida (process and port scanning)
  - Rooted devices (common binaries check)
- **Device Whitelisting** system
- **Tamper Response** (forced crash or server notification)

---

## 🛡️ Why Use Native Code for Security?

| Protection        | Java/Kotlin        | NDK (Native)              |
|------------------|--------------------|---------------------------|
| String Obfuscation | ❌ Easily decompiled | ✅ Encrypted at compile-time |
| Debugger Detection | ❌ Limited          | ✅ `/proc/self/status` access |
| Root Detection     | ❌ Bypassable       | ✅ Direct filesystem checks |
| Performance        | ⚡ Good             | 🚀 Excellent               |

---

## 🚀 Getting Started

### Prerequisites

- Android Studio (Arctic Fox or newer)
- NDK version 23+ (bundled with Android Studio)
- CMake 3.22+

### Installation

1. Add to your app's `build.gradle`:

```gradle
android {
    externalNativeBuild {
        cmake {
            path "src/main/cpp/CMakeLists.txt"
        }
    }
}
```

2. Load the native library in your Kotlin/Java class:

```kotlin
class NativeSecurity {
    companion object {
        init {
            System.loadLibrary("secureapi")
        }

        external fun getEncryptedApiKey(context: Context): String
        external fun isEnvironmentSecure(context: Context): Boolean
    }
}
```

---

## 🧩 Key Components

### 1. Encrypted Strings (`Constants.h`)

```cpp
// XOR-encrypted API key
const unsigned char ENCRYPTED_API_KEY[] = {
    0x32, 0x2E, 0x2E, 0x2A, 0x29, 0x60, 0x75, 0x75,
    0x2D, 0x2D, 0x2D, 0x74, 0x3D, 0x35, 0x35, 0x3D
};
```

### 2. Security Checks (`security_utils.cpp`)

```cpp
bool isDeviceRooted() {
    const char* paths[] = {"/sbin/su", "/system/bin/su"};
    for (const char* path : paths) {
        if (access(path, F_OK) == 0) return true;
    }
    return false;
}
```

### 3. JNI Interface (`native-lib.cpp`)

```cpp
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_NativeSecurity_getEncryptedApiKey(
    JNIEnv* env,
    jobject thiz,
    jobject context
) {
    if (!verifyAppSignature(env, context)) {
        return env->NewStringUTF("");
    }
    return env->NewStringUTF(decryptKey());
}
```

---

---

🔑 **Key Reference & Algorithm Explanation**

You can use the following link to understand the encryption algorithm and key generation process used in this project:

🔗 [OnlineGDB Secure Key Algorithm](https://www.onlinegdb.com/qwTUGS_5k)

> **Note:** The `SHA-256` hashes used in this project are formatted **without colons (`:`)** — they are plain 64-character hexadecimal strings.

## 📊 Performance Metrics

| Operation          | Java (ms) | NDK (ms) |
|-------------------|-----------|----------|
| String Decryption | 0.42      | 0.08     |
| Root Check        | 1.15      | 0.23     |
| Signature Verify  | 2.30      | 0.91     |

---

## 📜 License

Distributed under the Apache 2.0 License. See `LICENSE` for more information.

---

## 📬 Contact

**Chirag Vasani**  
📧 cpvasani48@gmail.com
📧 
