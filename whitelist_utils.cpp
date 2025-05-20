// whitelist_utils.cpp
#include "whitelist_utils.h"
#include "security_utils.h"
#include "Constants.h"
#include <android/log.h>
#include <fstream>
#include <thread>
#include <chrono>



bool fileExists(const std::string& path) {
    struct stat buffer;
    return stat(path.c_str(), &buffer) == 0;
}

bool isFileEmptyOrMissing(const std::string& path) {
    std::ifstream file(path);
    return !file.good() || file.peek() == std::ifstream::traits_type::eof();
}

std::vector<std::string> readWhitelist(const std::string& path) {
    std::vector<std::string> list;
    std::ifstream file(path);
    std::string line;
    while (std::getline(file, line)) {
        list.push_back(line);
    }
    return list;
}



std::string getStableDeviceId(JNIEnv *env) {
    // Get the class: com.yourpackage.utils.DeviceUtils
    jclass clazz = env->FindClass(Constants::APP_PACKAGE);
    if (clazz == nullptr) {
        return "ClassNotFound";
    }

    // Get the static method ID: generateStableDeviceId(): String
    jmethodID methodId = env->GetStaticMethodID(clazz, "generateStableDeviceId", "()Ljava/lang/String;");
    if (methodId == nullptr) {
        return "MethodNotFound";
    }

    // Call the static method
    jstring jDeviceId = (jstring) env->CallStaticObjectMethod(clazz, methodId);

    // Convert jstring to std::string
    const char *cStr = env->GetStringUTFChars(jDeviceId, nullptr);
    std::string result(cStr);
    env->ReleaseStringUTFChars(jDeviceId, cStr);
    env->DeleteLocalRef(jDeviceId);

    return result;
}

