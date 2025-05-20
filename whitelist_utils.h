// whitelist_utils.h
#ifndef WHITELIST_UTILS_H
#define WHITELIST_UTILS_H

#include <string>
#include <vector>
#include <sys/stat.h>
#include <jni.h>

bool fileExists(const std::string& path);
bool isFileEmptyOrMissing(const std::string& path);
std::vector<std::string> readWhitelist(const std::string& path);
std::string getStableDeviceId(JNIEnv* env);
//bool isDeviceWhitelistedForValidator(JNIEnv* env, jobject context, const std::string& deviceId);

#endif // WHITELIST_UTILS_H
