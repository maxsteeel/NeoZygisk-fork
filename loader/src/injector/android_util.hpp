#pragma once

#include <jni.h>
#include "logging.hpp"

namespace util {
namespace jni {

template <typename T>
class ScopedLocalRef {
public:
    using BaseType = T;

    explicit ScopedLocalRef(JNIEnv* env) noexcept : env_(env), ref_(nullptr) {}
    ScopedLocalRef(JNIEnv* env, T local_ref) : env_(env), ref_(local_ref) {}

    ScopedLocalRef(ScopedLocalRef&& other) noexcept : env_(other.env_), ref_(other.release()) {}

    template <typename U>
    ScopedLocalRef(ScopedLocalRef<U>&& other) noexcept
        : env_(other.env_), ref_(static_cast<T>(other.release())) {}

    ~ScopedLocalRef() { reset(); }

    ScopedLocalRef& operator=(ScopedLocalRef&& other) noexcept {
        if (this != &other) {
            reset(other.release());
            env_ = other.env_;
        }
        return *this;
    }

    ScopedLocalRef(const ScopedLocalRef&) = delete;
    ScopedLocalRef& operator=(const ScopedLocalRef&) = delete;

    void reset(T ptr = nullptr) {
        if (ref_ != ptr) {
            if (ref_ != nullptr) env_->DeleteLocalRef(ref_);
            ref_ = ptr;
        }
    }

    [[nodiscard]] T release() {
        T temp = ref_;
        ref_ = nullptr;
        return temp;
    }

    T get() const { return ref_; }
    operator T() const { return ref_; }
    operator bool() const { return ref_ != nullptr; }

    template <typename U> friend class ScopedLocalRef;

private:
    JNIEnv* env_;
    T ref_;
};

class JUTFString {
public:
    JUTFString(JNIEnv* env, jstring jstr) : env_(env), jstr_(jstr), cstr_(nullptr) {
        if (env_ && jstr_) cstr_ = env_->GetStringUTFChars(jstr_, nullptr);
    }

    ~JUTFString() {
        if (env_ && jstr_ && cstr_) env_->ReleaseStringUTFChars(jstr_, cstr_);
    }

    JUTFString(const JUTFString&) = delete;
    JUTFString& operator=(const JUTFString&) = delete;
    JUTFString(JUTFString&&) = delete;
    JUTFString& operator=(JUTFString&&) = delete;

    const char* get() const { return cstr_; }
    operator const char*() const { return cstr_; }
    operator bool() const { return cstr_ != nullptr; }

private:
    JNIEnv* env_;
    jstring jstr_;
    const char* cstr_;
};

#define JNI_CHECK_EXC(env, ret_val) \
    if (__builtin_expect(env->ExceptionCheck(), 0)) { \
        env->ExceptionDescribe(); \
        env->ExceptionClear(); \
        return ret_val; \
    }

inline ScopedLocalRef<jclass> FindClass(JNIEnv* env, const char* name) {
    jclass res = env->FindClass(name);
    JNI_CHECK_EXC(env, ScopedLocalRef<jclass>(env, nullptr));
    return ScopedLocalRef<jclass>(env, res);
}

inline jfieldID GetFieldID(JNIEnv* env, jclass clazz, const char* name, const char* sig) {
    jfieldID res = env->GetFieldID(clazz, name, sig);
    JNI_CHECK_EXC(env, nullptr);
    return res;
}

inline jfieldID GetStaticFieldID(JNIEnv* env, jclass clazz, const char* name, const char* sig) {
    jfieldID res = env->GetStaticFieldID(clazz, name, sig);
    JNI_CHECK_EXC(env, nullptr);
    return res;
}

inline ScopedLocalRef<jobject> GetObjectField(JNIEnv* env, jobject obj, jfieldID fieldId) {
    jobject res = env->GetObjectField(obj, fieldId);
    JNI_CHECK_EXC(env, ScopedLocalRef<jobject>(env, nullptr));
    return ScopedLocalRef<jobject>(env, res);
}

inline void SetObjectField(JNIEnv* env, jobject obj, jfieldID fieldId, jobject value) {
    env->SetObjectField(obj, fieldId, value);
    JNI_CHECK_EXC(env, );
}

inline jint GetStaticIntField(JNIEnv* env, jclass clazz, jfieldID fieldId) {
    jint res = env->GetStaticIntField(clazz, fieldId);
    JNI_CHECK_EXC(env, 0);
    return res;
}

inline jmethodID GetMethodID(JNIEnv* env, jclass clazz, const char* name, const char* sig) {
    jmethodID res = env->GetMethodID(clazz, name, sig);
    JNI_CHECK_EXC(env, nullptr);
    return res;
}

inline ScopedLocalRef<jobject> ToReflectedMethod(JNIEnv* env, jclass clazz, jmethodID method, jboolean isStatic) {
    jobject res = env->ToReflectedMethod(clazz, method, isStatic);
    JNI_CHECK_EXC(env, ScopedLocalRef<jobject>(env, nullptr));
    return ScopedLocalRef<jobject>(env, res);
}

template <typename... Args>
inline void CallVoidMethod(JNIEnv* env, jobject obj, jmethodID method, Args... args) {
    env->CallVoidMethod(obj, method, args...);
    JNI_CHECK_EXC(env, );
}

template <typename... Args>
inline ScopedLocalRef<jobject> CallObjectMethod(JNIEnv* env, jobject obj, jmethodID method, Args... args) {
    jobject res = env->CallObjectMethod(obj, method, args...);
    JNI_CHECK_EXC(env, ScopedLocalRef<jobject>(env, nullptr));
    return ScopedLocalRef<jobject>(env, res);
}

template <typename... Args>
inline jboolean CallBooleanMethod(JNIEnv* env, jobject obj, jmethodID method, Args... args) {
    jboolean res = env->CallBooleanMethod(obj, method, args...);
    JNI_CHECK_EXC(env, JNI_FALSE);
    return res;
}

template <typename... Args>
inline jint CallIntMethod(JNIEnv* env, jobject obj, jmethodID method, Args... args) {
    jint res = env->CallIntMethod(obj, method, args...);
    JNI_CHECK_EXC(env, 0);
    return res;
}

inline jlong GetLongField(JNIEnv* env, jobject obj, jfieldID fieldId) {
    jlong res = env->GetLongField(obj, fieldId);
    JNI_CHECK_EXC(env, 0);
    return res;
}

template <typename... Args>
inline ScopedLocalRef<jobject> NewObject(JNIEnv* env, jclass clazz, jmethodID method, Args... args) {
    jobject res = env->NewObject(clazz, method, args...);
    JNI_CHECK_EXC(env, ScopedLocalRef<jobject>(env, nullptr));
    return ScopedLocalRef<jobject>(env, res);
}

inline ScopedLocalRef<jstring> NewStringUTF(JNIEnv* env, const char* str) {
    jstring res = env->NewStringUTF(str);
    JNI_CHECK_EXC(env, ScopedLocalRef<jstring>(env, nullptr));
    return ScopedLocalRef<jstring>(env, res);
}

template <typename U, typename T>
inline ScopedLocalRef<U> Cast(ScopedLocalRef<T>&& x) {
    return ScopedLocalRef<U>(static_cast<ScopedLocalRef<T>&&>(x));
}

}  // namespace jni

namespace art {

class ArtMethod {
public:
    void* GetData() {
        return *reinterpret_cast<void**>(reinterpret_cast<uintptr_t>(this) + data_offset);
    }

    static ArtMethod* FromReflectedMethod(JNIEnv* env, jobject method) {
        if (!art_method_field_id_) return nullptr;
        jlong art_method_ptr = jni::GetLongField(env, method, art_method_field_id_);
        return reinterpret_cast<ArtMethod*>(art_method_ptr);
    }

    static bool Init(JNIEnv* env) {
        if (art_method_field_id_) return true; 

        auto executable_class = jni::FindClass(env, "java/lang/reflect/Executable");
        if (!executable_class) {
            LOGE("could not find java.lang.reflect.Executable");
            return false;
        }

        art_method_field_id_ = jni::GetFieldID(env, executable_class, "artMethod", "J");
        if (!art_method_field_id_) {
            LOGE("failed to find field 'artMethod' in Executable class");
            return false;
        }

        auto throwable_class = jni::FindClass(env, "java/lang/Throwable");
        if (!throwable_class) {
            LOGE("could not find java.lang.Throwable");
            return false;
        }
        
        auto class_class = jni::FindClass(env, "java/lang/Class");
        jmethodID get_constructors_method = jni::GetMethodID(
            env, class_class, "getDeclaredConstructors", "()[Ljava/lang/reflect/Constructor;");
            
        auto constructors_array = jni::Cast<jobjectArray>(
            jni::CallObjectMethod(env, throwable_class, get_constructors_method));

        if (!constructors_array || env->GetArrayLength(constructors_array.get()) < 2) {
            LOGE("throwable has less than 2 constructors, cannot determine ArtMethod size.");
            return false;
        }

        auto first_ctor = jni::ScopedLocalRef<jobject>(
            env, env->GetObjectArrayElement(constructors_array.get(), 0));
        auto second_ctor = jni::ScopedLocalRef<jobject>(
            env, env->GetObjectArrayElement(constructors_array.get(), 1));

        auto* first = FromReflectedMethod(env, first_ctor.get());
        auto* second = FromReflectedMethod(env, second_ctor.get());

        if (!first || !second) {
            LOGE("failed to get ArtMethod pointers from constructors.");
            return false;
        }

        art_method_size = reinterpret_cast<uintptr_t>(second) - reinterpret_cast<uintptr_t>(first);
        constexpr auto kPointerSize = sizeof(void*);
        entry_point_offset = art_method_size - kPointerSize;
        data_offset = entry_point_offset - kPointerSize;

        LOGV("ArtMethod size: %zu, data offset: %zu", art_method_size, data_offset);
        return true;
    }

private:
    inline static jfieldID art_method_field_id_ = nullptr;
    inline static size_t art_method_size = 0;
    inline static size_t entry_point_offset = 0;
    inline static size_t data_offset = 0;
};

}  // namespace art
}  // namespace util
