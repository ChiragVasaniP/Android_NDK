// native-lib.cpp
#include <jni.h>
#include <string>
#include <android/log.h>
#include <thread>
#include <chrono>
#include <fstream>
#include <sys/stat.h>
#include "security_utils.h"
#include "whitelist_utils.h"
#include "Constants.h"




// --- Constants for encrypted strings (XOR) ---
const char XOR_KEY = 0x5A;



const size_t ENCRYPTED_APP_SERVER_URL_LEN = sizeof(Constants::ENCRYPTED_APP_SERVER_URL);

const unsigned char ENCRYPTED_GEN_SERVER_URL[] = {
        0x32, 0x2E, 0x2E, 0x2A, 0x29, 0x60, 0x75, 0x75,
        0x2D, 0x2D, 0x2D, 0x74, 0x3D, 0x35, 0x35, 0x3D,
        0x36, 0x3F, 0x74, 0x39, 0x35, 0x37, 0x75
};
const size_t ENCRYPTED_GEN_SERVER_URL_LEN = sizeof(ENCRYPTED_GEN_SERVER_URL);


const size_t ENCRYPTED_SECURITY_KEY_LEN = sizeof(Constants::ENCRYPTED_SECURITY_KEY);


const unsigned char ENCRYPTED_CRYPT_SECURITY_KEY[] = {
        0x39, 0x28, 0x23, 0x2A, 0x2E, 0x0F, 0x29, 0x3F, 0x28, 0x11, 0x3F, 0x23
};

const size_t ENCRYPTED_CRYPT_SECURITY_KEY_LEN = sizeof(ENCRYPTED_CRYPT_SECURITY_KEY);


extern "C"
__attribute__((visibility("default")))
jstring JNICALL
JNI_METHOD(getServerUrl)(JNIEnv *env, jobject,jobject context) {
    if(verifyAppSignature(env, context)){
        std::string url = xorDecrypt(Constants::ENCRYPTED_APP_SERVER_URL, ENCRYPTED_APP_SERVER_URL_LEN, XOR_KEY);
        return env->NewStringUTF(url.c_str());
    }else return env->NewStringUTF("");

}

extern "C"
__attribute__((visibility("default")))
jstring JNICALL
JNI_METHOD(getGeneralUrl)(JNIEnv *env, jobject,jobject context) {
    if(verifyAppSignature(env, context)){
        std::string url = xorDecrypt(ENCRYPTED_GEN_SERVER_URL, ENCRYPTED_GEN_SERVER_URL_LEN, XOR_KEY);
        return env->NewStringUTF(url.c_str());
    }else return env->NewStringUTF("");

}


extern "C"
__attribute__((visibility("default")))
jstring JNICALL
JNI_METHOD(getDecryptKey)(JNIEnv *env, jobject,jobject context) {
    std::string cyptedKey = xorDecrypt(ENCRYPTED_CRYPT_SECURITY_KEY, ENCRYPTED_CRYPT_SECURITY_KEY_LEN, XOR_KEY);
    if(verifyAppSignature(env, context)){
        std::string key = xorDecrypt(Constants::ENCRYPTED_SECURITY_KEY, ENCRYPTED_SECURITY_KEY_LEN, XOR_KEY);
        if (detectFrida()) return env->NewStringUTF(cyptedKey.c_str());
        if (isDeviceRooted()) return env->NewStringUTF(cyptedKey.c_str());
        if (isDebuggerAttached()) return env->NewStringUTF(cyptedKey.c_str());
        return env->NewStringUTF(key.c_str());
    }else{
        return env->NewStringUTF(cyptedKey.c_str());
    }


}

extern "C"
__attribute__((visibility("default")))
jboolean JNICALL
JNI_METHOD(isFridaRunning)(JNIEnv *env, jobject,jobject context) {
    std::string fetchedDeviceId = getStableDeviceId(env);
    if (!verifyAppSignature(env, context)) {
        return JNI_FALSE;
    } else {
        return (detectFrida() || checkFridaPorts()) ? JNI_TRUE : JNI_FALSE;
    }
}

extern "C"
__attribute__((visibility("default")))
jboolean JNICALL
JNI_METHOD(isDebuggerAttached)(JNIEnv *env, jobject,jobject context) {
    std::string fetchedDeviceId = getStableDeviceId(env);
    if (!verifyAppSignature(env, context)) {
        return JNI_FALSE;
    } else {
        return isDebuggerAttached() ? JNI_TRUE : JNI_FALSE;
    }


}

extern "C"
__attribute__((visibility("default")))
jboolean JNICALL
JNI_METHOD(isDeviceRooted)(JNIEnv *env, jobject,jobject context) {
    std::string fetchedDeviceId = getStableDeviceId(env);
    if (verifyAppSignature(env, context)) {
        return JNI_FALSE;
    } else {
        return isDeviceRooted() ? JNI_TRUE : JNI_FALSE;
    }
}

extern "C"
__attribute__((visibility("default")))
JNIEXPORT jboolean JNICALL
JNI_METHOD(isAdbOrDevModeEnabled)(
        JNIEnv *env,
        jobject /* this */,
        jobject context,
        jstring deviceIdJ) {
    const char *deviceId = env->GetStringUTFChars(deviceIdJ, nullptr);
    std::string deviceStr(deviceId);
    env->ReleaseStringUTFChars(deviceIdJ, deviceId);

    jclass contextClass = env->GetObjectClass(context);
    jmethodID getContentResolver = env->GetMethodID(contextClass, "getContentResolver",
                                                    "()Landroid/content/ContentResolver;");
    jobject contentResolver = env->CallObjectMethod(context, getContentResolver);

    jclass settingsGlobal = env->FindClass("android/provider/Settings$Global");
    jmethodID getIntMethod = env->GetStaticMethodID(settingsGlobal, "getInt",
                                                    "(Landroid/content/ContentResolver;Ljava/lang/String;I)I");

    jstring adbKey = env->NewStringUTF("adb_enabled");
    jstring devKey = env->NewStringUTF("development_settings_enabled");

    jint adbEnabled = env->CallStaticIntMethod(settingsGlobal, getIntMethod, contentResolver,
                                               adbKey, 0);
    jint devEnabled = env->CallStaticIntMethod(settingsGlobal, getIntMethod, contentResolver,
                                               devKey, 0);

    env->DeleteLocalRef(adbKey);
    env->DeleteLocalRef(devKey);
    env->DeleteLocalRef(settingsGlobal);
    env->DeleteLocalRef(contentResolver);
    env->DeleteLocalRef(contextClass);

    LOGI("ADB Enabled: %d, Dev Settings Enabled: %d", adbEnabled, devEnabled);
    return (adbEnabled == 1 || devEnabled == 1) ? JNI_TRUE : JNI_FALSE;
}
