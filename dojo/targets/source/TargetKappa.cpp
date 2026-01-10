#include <jni.h>
#include <string.h>

extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_kappa_NativeLib_checkLicense(JNIEnv* env, jobject /* this */) {
    // VULNERABILITY: Native boolean check.
    // Agent must use Interceptor.attach on this symbol.
    return false;
}
