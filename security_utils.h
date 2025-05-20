// security_utils.h
#ifndef SECURITY_UTILS_H
#define SECURITY_UTILS_H

#include <string>
#include <jni.h>

std::string xorDecrypt(const unsigned char* data, size_t len, char key);
bool detectFrida();
bool checkFridaPorts();
bool isDebuggerAttached();
bool isDeviceRooted();
bool verifyAppSignature(JNIEnv* env, jobject context);
bool isInstalledFromPlayStore(JNIEnv* env, jobject context);
bool isApkPathValid(JNIEnv* env, jobject context);
void forceCrashDueToTampering(JNIEnv* env,jobject context);

#endif // SECURITY_UTILS_H
