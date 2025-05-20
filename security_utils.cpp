// security_utils.cpp
#include "security_utils.h"
#include "whitelist_utils.h"
#include "Constants.h"
#include <android/log.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fstream>
#include <jni.h>

const size_t ENCRYPTED_DEBUG_KEY_LEN = sizeof(Constants:: ENCRYPTED_DEBUG_KEY);


const size_t ENCRYPTED_SIGINING_KEY_LEN = sizeof(Constants::ENCRYPTED_SIGINING_KEY);


const size_t ENCRYPTED_GOOGLE_SIGINING_KEY_LEN = sizeof(Constants::ENCRYPTED_GOOGLE_SIGINING_KEY);


const char XOR_KEY = 0x5A;

std::string xorDecrypt(const unsigned char *data, size_t len, char key) {
    std::string result;
    result.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        result.push_back(data[i] ^ key);
    }
    return result;
}

bool detectFrida() {
    DIR* dir = opendir("/proc");
    if (!dir) return false;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        int pid = atoi(entry->d_name);
        if (pid <= 0) continue;

        char path[256];
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        int fd = open(path, O_RDONLY);
        if (fd < 0) continue;

        char cmdline[256] = {0};
        read(fd, cmdline, sizeof(cmdline) - 1);
        close(fd);

        if (strstr(cmdline, "frida") || strstr(cmdline, "gum-js-loop")) {
            LOGI("Frida detected: %s", cmdline);
            closedir(dir);
            return true;
        }
    }
    closedir(dir);
    return false;
}

bool checkFridaPorts() {
    int ports[] = {27042, 27043};
    for (int port : ports) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        struct sockaddr_in serv_addr {};
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);
        serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        int result = connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
        close(sock);

        if (result == 0) {
            LOGI("Frida port open: %d", port);
            return true;
        }
    }
    return false;
}

bool isDebuggerAttached() {
    std::ifstream statusFile("/proc/self/status");
    std::string line;
    while (std::getline(statusFile, line)) {
        if (line.find("TracerPid:") != std::string::npos) {
            int tracerPid = std::stoi(line.substr(line.find(":") + 1));
            if (tracerPid != 0) {
                LOGI("Debugger detected via TracerPid: %d", tracerPid);
                return true;
            }
            break;
        }
    }
    return false;
}

bool isDeviceRooted() {
    const char* paths[] = {
            "/system/app/Superuser.apk",
            "/sbin/su", "/system/bin/su", "/system/xbin/su",
            "/data/local/xbin/su", "/data/local/bin/su"
    };

    for (const char* path : paths) {
        if (access(path, F_OK) == 0) {
            LOGI("Root detected at: %s", path);
            return true;
        }
    }
    return false;
}
bool isInstalledFromPlayStore(JNIEnv* env, jobject context) {
    jclass contextClass = env->GetObjectClass(context);
    jmethodID getPackageManager = env->GetMethodID(contextClass, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jobject packageManager = env->CallObjectMethod(context, getPackageManager);

    jmethodID getPackageName = env->GetMethodID(contextClass, "getPackageName", "()Ljava/lang/String;");
    jstring packageName = (jstring)env->CallObjectMethod(context, getPackageName);

    jclass pmClass = env->GetObjectClass(packageManager);
    jmethodID getInstallerPackageName = env->GetMethodID(pmClass, "getInstallerPackageName", "(Ljava/lang/String;)Ljava/lang/String;");
    jstring installerName = (jstring)env->CallObjectMethod(packageManager, getInstallerPackageName, packageName);

    if (installerName == nullptr) {
        return false; // Sideloaded (no installer)
    }

    const char* installerStr = env->GetStringUTFChars(installerName, nullptr);
    bool isPlayStore = (strcmp(installerStr, "com.android.vending") == 0 || strcmp(installerStr, "com.google.android.feedback") == 0);
    env->ReleaseStringUTFChars(installerName, installerStr);

    return isPlayStore;
}


bool isApkPathValid(JNIEnv* env, jobject context) {
    jclass contextClass = env->GetObjectClass(context);
    jmethodID getApplicationInfo = env->GetMethodID(contextClass, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
    jobject appInfo = env->CallObjectMethod(context, getApplicationInfo);

    jclass appInfoClass = env->GetObjectClass(appInfo);
    jfieldID sourceDirField = env->GetFieldID(appInfoClass, "sourceDir", "Ljava/lang/String;");
    jstring sourceDir = (jstring)env->GetObjectField(appInfo, sourceDirField);

    const char* path = env->GetStringUTFChars(sourceDir, nullptr);
    bool isValidPath = (strstr(path, "/data/app/") != nullptr || strstr(path, "/system/app/") != nullptr);
    env->ReleaseStringUTFChars(sourceDir, path);

    return isValidPath;
}


bool isCallerValid(JNIEnv* env, jobject context) {
    // 1. Get PackageManager

    std::string fetchedDeviceId = getStableDeviceId(env);
    jclass contextClass = env->GetObjectClass(context);
    jmethodID getPackageManager = env->GetMethodID(contextClass, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jobject packageManager = env->CallObjectMethod(context, getPackageManager);

    // 2. Get package name
    jmethodID getPackageName = env->GetMethodID(contextClass, "getPackageName", "()Ljava/lang/String;");
    jstring packageName = (jstring) env->CallObjectMethod(context, getPackageName);

    // 3. Get Signature[] using PackageManager.getPackageInfo()
    jclass pmClass = env->GetObjectClass(packageManager);
    jmethodID getPackageInfo = env->GetMethodID(pmClass, "getPackageInfo",
                                                "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    jobject packageInfo = env->CallObjectMethod(
            packageManager,
            getPackageInfo,
            packageName,
            0x40 // PackageManager.GET_SIGNATURES
    );

    // 4. Get first signature
    jclass packageInfoClass = env->GetObjectClass(packageInfo);
    jfieldID signaturesField = env->GetFieldID(packageInfoClass, "signatures", "[Landroid/content/pm/Signature;");
    jobjectArray signatures = (jobjectArray) env->GetObjectField(packageInfo, signaturesField);
    jobject signature = env->GetObjectArrayElement(signatures, 0);

    // 5. toByteArray
    jclass signatureClass = env->GetObjectClass(signature);
    jmethodID toByteArray = env->GetMethodID(signatureClass, "toByteArray", "()[B");
    jbyteArray sigBytes = (jbyteArray) env->CallObjectMethod(signature, toByteArray);

    // 6. Get SHA-256
    jclass messageDigestClass = env->FindClass("java/security/MessageDigest");
    jmethodID getInstance = env->GetStaticMethodID(messageDigestClass, "getInstance",
                                                   "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    jstring algo = env->NewStringUTF("SHA-256");
    jobject digest = env->CallStaticObjectMethod(messageDigestClass, getInstance, algo);

    jmethodID update = env->GetMethodID(messageDigestClass, "update", "([B)V");
    env->CallVoidMethod(digest, update, sigBytes);

    jmethodID digestMethod = env->GetMethodID(messageDigestClass, "digest", "()[B");
    jbyteArray hashBytes = (jbyteArray) env->CallObjectMethod(digest, digestMethod);

    // 7. Convert to hex
    jsize length = env->GetArrayLength(hashBytes);
    jbyte* hashData = env->GetByteArrayElements(hashBytes, nullptr);

    std::string hexHash;
    char buffer[3];
    for (int i = 0; i < length; ++i) {
        sprintf(buffer, "%02X", (unsigned char) hashData[i]);
        hexHash.append(buffer);
    }

    env->ReleaseByteArrayElements(hashBytes, hashData, JNI_ABORT);

//    TODO SHA 256 Code
    std::string debugKey = xorDecrypt(Constants::ENCRYPTED_DEBUG_KEY, ENCRYPTED_DEBUG_KEY_LEN, XOR_KEY);
    std::string siginingKey = xorDecrypt(Constants::ENCRYPTED_SIGINING_KEY, ENCRYPTED_SIGINING_KEY_LEN, XOR_KEY);
    std::string googleSiginingKey = xorDecrypt(Constants::ENCRYPTED_GOOGLE_SIGINING_KEY, ENCRYPTED_GOOGLE_SIGINING_KEY_LEN, XOR_KEY);
    // 8. Compare with expected hash
    std::vector<std::string> validHashes = {
            xorDecrypt(Constants::ENCRYPTED_DEBUG_KEY, ENCRYPTED_DEBUG_KEY_LEN, XOR_KEY),
            siginingKey,
            googleSiginingKey
    };
//    || isInstalledFromPlayStore(env,context)
    for (const auto& trusted : validHashes) {
        if (hexHash == trusted ) {
            LOGI("Signature matched: %s", hexHash.c_str());
            return true;
        }
    }

    if (!isDeviceWhitelisted(env, context, fetchedDeviceId)) {
        forceCrashDueToTampering(env, context);
    }
//    forceCrashDueToTampering(env, context);
    LOGI("Signature mismatch: %s", hexHash.c_str());
    return false;
}


bool verifyAppSignature(JNIEnv* env, jobject context) {
    return isCallerValid(env, context);
}




void forceCrashDueToTampering(JNIEnv* env, jobject context) {
    jclass fetcherClass = env->FindClass(Constants::APP_PACKAGE);
    if (!fetcherClass) {
        LOGI("Failed to find fetcher class");
        return;
    }

    jmethodID fetchMethod = env->GetStaticMethodID(fetcherClass, "onTamperingDetected", "()V");
    if (!fetchMethod) {
        LOGI("Failed to find fetch method");
        return;
    }

    env->CallStaticVoidMethod(fetcherClass, fetchMethod);
    LOGI("Triggered whitelist fetch via Kotlin");
    env->DeleteLocalRef(fetcherClass);
}

void forceCrash(JNIEnv *env) {
    LOGI("Force crash triggered: ");
    jclass secException = env->FindClass("java/lang/SecurityException");
    if (secException != nullptr) {
        env->ThrowNew(secException, "Alert Hacking Found");
    } else abort();
}

