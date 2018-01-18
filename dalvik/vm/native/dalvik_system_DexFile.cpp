/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * dalvik.system.DexFile
 */
#include "Dalvik.h"
#include "native/InternalNativePriv.h"

/*
 * Return true if the given name ends with ".dex".
 */
static bool hasDexExtension(const char* name) {
    size_t len = strlen(name);

    return (len >= 5)
        && (name[len - 5] != '/')
        && (strcmp(&name[len - 4], ".dex") == 0);
}

/*
 * Internal struct for managing DexFile.
 */
struct DexOrJar {
    char*       fileName;
    bool        isDex;
    bool        okayToFree;
    RawDexFile* pRawDexFile;
    JarFile*    pJarFile;
    u1*         pDexMemory; // malloc()ed memory, if any
};

/*
 * (This is a dvmHashTableFree callback.)
 */
void dvmFreeDexOrJar(void* vptr)
{
    DexOrJar* pDexOrJar = (DexOrJar*) vptr;

    ALOGV("Freeing DexOrJar '%s'", pDexOrJar->fileName);

    if (pDexOrJar->isDex)
        dvmRawDexFileFree(pDexOrJar->pRawDexFile);
    else
        dvmJarFileFree(pDexOrJar->pJarFile);
    free(pDexOrJar->fileName);
    free(pDexOrJar->pDexMemory);
    free(pDexOrJar);
}

/*
 * (This is a dvmHashTableLookup compare func.)
 *
 * Args are DexOrJar*.
 */
static int hashcmpDexOrJar(const void* tableVal, const void* newVal)
{
    return (int) newVal - (int) tableVal;
}

/*
 * Verify that the "cookie" is a DEX file we opened.
 *
 * Expects that the hash table will be *unlocked* here.
 *
 * If the cookie is invalid, we throw an exception and return "false".
 */
static bool validateCookie(int cookie)
{
    DexOrJar* pDexOrJar = (DexOrJar*) cookie;

    LOGVV("+++ dex verifying cookie %p", pDexOrJar);

    if (pDexOrJar == NULL)
        return false;

    u4 hash = cookie;
    dvmHashTableLock(gDvm.userDexFiles);
    void* result = dvmHashTableLookup(gDvm.userDexFiles, hash, pDexOrJar,
                hashcmpDexOrJar, false);
    dvmHashTableUnlock(gDvm.userDexFiles);
    if (result == NULL) {
        dvmThrowRuntimeException("invalid DexFile cookie");
        return false;
    }

    return true;
}


/*
 * Add given DexOrJar to the hash table of user-loaded dex files.
 */
static void addToDexFileTable(DexOrJar* pDexOrJar) {
    /*
     * Later on, we will receive this pointer as an argument and need
     * to find it in the hash table without knowing if it's valid or
     * not, which means we can't compute a hash value from anything
     * inside DexOrJar. We don't share DexOrJar structs when the same
     * file is opened multiple times, so we can just use the low 32
     * bits of the pointer as the hash.
     */
    u4 hash = (u4) pDexOrJar;
    void* result;

    dvmHashTableLock(gDvm.userDexFiles);
    result = dvmHashTableLookup(gDvm.userDexFiles, hash, pDexOrJar,
            hashcmpDexOrJar, true);
    dvmHashTableUnlock(gDvm.userDexFiles);

    if (result != pDexOrJar) {
        ALOGE("Pointer has already been added?");
        dvmAbort();
    }

    pDexOrJar->okayToFree = true;

}

/*
 * private static int openDexFileNative(String sourceName, String outputName,
 *     int flags) throws IOException
 *
 * Open a DEX file, returning a pointer to our internal data structure.
 *
 * "sourceName" should point to the "source" jar or DEX file.
 *
 * If "outputName" is NULL, the DEX code will automatically find the
 * "optimized" version in the cache directory, creating it if necessary.
 * If it's non-NULL, the specified file will be used instead.
 *
 * TODO: at present we will happily open the same file more than once.
 * To optimize this away we could search for existing entries in the hash
 * table and refCount them.  Requires atomic ops or adding "synchronized"
 * to the non-native code that calls here.
 *
 * TODO: should be using "long" for a pointer.
 */
static void Dalvik_dalvik_system_DexFile_openDexFileNative(const u4* args,
    JValue* pResult)
{
    StringObject* sourceNameObj = (StringObject*) args[0];
    StringObject* outputNameObj = (StringObject*) args[1];
    DexOrJar* pDexOrJar = NULL;
    JarFile* pJarFile;
    RawDexFile* pRawDexFile;
    char* sourceName;
    char* outputName;

    if (sourceNameObj == NULL) {
        dvmThrowNullPointerException("sourceName == null");
        RETURN_VOID();
    }

    sourceName = dvmCreateCstrFromString(sourceNameObj);
    if (outputNameObj != NULL)
        outputName = dvmCreateCstrFromString(outputNameObj);
    else
        outputName = NULL;

    /*
     * We have to deal with the possibility that somebody might try to
     * open one of our bootstrap class DEX files.  The set of dependencies
     * will be different, and hence the results of optimization might be
     * different, which means we'd actually need to have two versions of
     * the optimized DEX: one that only knows about part of the boot class
     * path, and one that knows about everything in it.  The latter might
     * optimize field/method accesses based on a class that appeared later
     * in the class path.
     *
     * We can't let the user-defined class loader open it and start using
     * the classes, since the optimized form of the code skips some of
     * the method and field resolution that we would ordinarily do, and
     * we'd have the wrong semantics.
     *
     * We have to reject attempts to manually open a DEX file from the boot
     * class path.  The easiest way to do this is by filename, which works
     * out because variations in name (e.g. "/system/framework/./ext.jar")
     * result in us hitting a different dalvik-cache entry.  It's also fine
     * if the caller specifies their own output file.
     */
    if (dvmClassPathContains(gDvm.bootClassPath, sourceName)) {
        ALOGW("Refusing to reopen boot DEX '%s'", sourceName);
        dvmThrowIOException(
            "Re-opening BOOTCLASSPATH DEX files is not allowed");
        free(sourceName);
        free(outputName);
        RETURN_VOID();
    }

    /*
     * Try to open it directly as a DEX if the name ends with ".dex".
     * If that fails (or isn't tried in the first place), try it as a
     * Zip with a "classes.dex" inside.
     */
    if (hasDexExtension(sourceName)
            && dvmRawDexFileOpen(sourceName, outputName, &pRawDexFile, false) == 0) {
        ALOGV("Opening DEX file '%s' (DEX)", sourceName);

        pDexOrJar = (DexOrJar*) malloc(sizeof(DexOrJar));
        pDexOrJar->isDex = true;
        pDexOrJar->pRawDexFile = pRawDexFile;
        pDexOrJar->pDexMemory = NULL;
    } else if (dvmJarFileOpen(sourceName, outputName, &pJarFile, false) == 0) {
        ALOGV("Opening DEX file '%s' (Jar)", sourceName);

        pDexOrJar = (DexOrJar*) malloc(sizeof(DexOrJar));
        pDexOrJar->isDex = false;
        pDexOrJar->pJarFile = pJarFile;
        pDexOrJar->pDexMemory = NULL;
    } else {
        ALOGV("Unable to open DEX file '%s'", sourceName);
        dvmThrowIOException("unable to open DEX file");
    }

    if (pDexOrJar != NULL) {
        pDexOrJar->fileName = sourceName;
        addToDexFileTable(pDexOrJar);
    } else {
        free(sourceName);
    }

    free(outputName);
    RETURN_PTR(pDexOrJar);
}

/*
 * private static int openDexFile(byte[] fileContents) throws IOException
 *
 * Open a DEX file represented in a byte[], returning a pointer to our
 * internal data structure.
 *
 * The system will only perform "essential" optimizations on the given file.
 *
 * TODO: should be using "long" for a pointer.
 */
static void Dalvik_dalvik_system_DexFile_openDexFile_bytearray(const u4* args,
    JValue* pResult)
{
    ArrayObject* fileContentsObj = (ArrayObject*) args[0];
    u4 length;
    u1* pBytes;
    RawDexFile* pRawDexFile;
    DexOrJar* pDexOrJar = NULL;

    if (fileContentsObj == NULL) {
        dvmThrowNullPointerException("fileContents == null");
        RETURN_VOID();
    }

    /* TODO: Avoid making a copy of the array. (note array *is* modified) */
    length = fileContentsObj->length;
    pBytes = (u1*) malloc(length);

    if (pBytes == NULL) {
        dvmThrowRuntimeException("unable to allocate DEX memory");
        RETURN_VOID();
    }

    memcpy(pBytes, fileContentsObj->contents, length);

    if (dvmRawDexFileOpenArray(pBytes, length, &pRawDexFile) != 0) {
        ALOGV("Unable to open in-memory DEX file");
        free(pBytes);
        dvmThrowRuntimeException("unable to open in-memory DEX file");
        RETURN_VOID();
    }

    ALOGV("Opening in-memory DEX");
    pDexOrJar = (DexOrJar*) malloc(sizeof(DexOrJar));
    pDexOrJar->isDex = true;
    pDexOrJar->pRawDexFile = pRawDexFile;
    pDexOrJar->pDexMemory = pBytes;
    pDexOrJar->fileName = strdup("<memory>"); // Needs to be free()able.
    addToDexFileTable(pDexOrJar);

    RETURN_PTR(pDexOrJar);
}

/*
 * private static void closeDexFile(int cookie)
 *
 * Release resources associated with a user-loaded DEX file.
 */
static void Dalvik_dalvik_system_DexFile_closeDexFile(const u4* args,
    JValue* pResult)
{
    int cookie = args[0];
    DexOrJar* pDexOrJar = (DexOrJar*) cookie;

    if (pDexOrJar == NULL)
        RETURN_VOID();
    if (!validateCookie(cookie))
        RETURN_VOID();

    ALOGV("Closing DEX file %p (%s)", pDexOrJar, pDexOrJar->fileName);


    /*
     * We can't just free arbitrary DEX files because they have bits and
     * pieces of loaded classes.  The only exception to this rule is if
     * they were never used to load classes.
     *
     * If we can't free them here, dvmInternalNativeShutdown() will free
     * them when the VM shuts down.
     */
    if (pDexOrJar->okayToFree) {
        u4 hash = (u4) pDexOrJar;
        dvmHashTableLock(gDvm.userDexFiles);
        if (!dvmHashTableRemove(gDvm.userDexFiles, hash, pDexOrJar)) {
            ALOGW("WARNING: could not remove '%s' from DEX hash table",
                pDexOrJar->fileName);
        }
        dvmHashTableUnlock(gDvm.userDexFiles);
        ALOGV("+++ freeing DexFile '%s' resources", pDexOrJar->fileName);
        dvmFreeDexOrJar(pDexOrJar);
    } else {
        ALOGV("+++ NOT freeing DexFile '%s' resources", pDexOrJar->fileName);
    }

    RETURN_VOID();
}


//=========================instrumentation start=========================//
#include "libdex/DexClass.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/syscall.h>

int pkg_id = 100000;
char pkgname[100] = {0}; // the package name of the app to be analyzed

char enable_class_detection[10] = {0};
char enable_java_method_trace[10] = {0};

char enable_jni_j2n_trace[10] = {0}; 
char enable_jni_n2j_trace[10] = {0}; 

char enable_lib_trace[10] = {0}; // must enable_jni_j2n_trace before enable_lib_trace

char dex_class_name[100] = {0};
char dex_method_name[100] = {0};

/* JNI force return */
char j2n_function_name[100] = {0};
char j2n_function_return_value[ARRAY_SIZE] = {0};
char j2n_function_arg_index[10] = {0};
char j2n_function_arg_length[10] = {0};
char j2n_function_arg_value[ARRAY_SIZE] = {0};
char n2j_function_name[100] = {0};
char n2j_function_return_value[ARRAY_SIZE] = {0};

static bool config_readable = true;
static pthread_mutex_t config_read_mutex;
static bool d_flag = true;
//static bool l_flag = true;

/* read the configuration file */
void* read_config(void* arg) {
    FILE* fp = NULL;
    char content[ARRAY_SIZE] = {0};
    char** result = NULL;
    char token[] = " =";

    result = (char**) malloc(sizeof(char*) * 2);
    if (result == NULL) {
        return NULL;
    }

    while (pkgname[0] == 0) {
        fp = fopen("/data/config", "r");
        if (fp == NULL) {
            sleep(1);
            continue;
        }

        while(fgets(content, sizeof(content), fp) != NULL) {
            
            int count = 0;
            char tmp[ARRAY_SIZE] = {0};
            strcpy(tmp, content);
            char* pch = strtok(tmp, token);
            
            while(pch != NULL) {
                *(result + count) = pch;
                pch = strtok(NULL, token);
                count++;
            }

            if (strcmp(result[0], "pkgname") == 0) {
                strcpy(pkgname, result[1]);
                pkgname[strlen(pkgname)-1] = 0;
            } else if (strcmp(result[0], "enable_class_detection") == 0) {
                strcpy(enable_class_detection, result[1]);
                enable_class_detection[strlen(enable_class_detection)-1] = 0;
            } else if (strcmp(result[0], "enable_java_method_trace") == 0) {
                strcpy(enable_java_method_trace, result[1]);
                enable_java_method_trace[strlen(enable_java_method_trace)-1] = 0;
            } else if (strcmp(result[0], "enable_lib_trace") == 0) {
                strcpy(enable_lib_trace, result[1]);
                enable_lib_trace[strlen(enable_lib_trace)-1] = 0;
            } else if (strcmp(result[0], "enable_jni_j2n_trace") == 0) {
                strcpy(enable_jni_j2n_trace, result[1]);
                enable_jni_j2n_trace[strlen(enable_jni_j2n_trace)-1] = 0;
            } else if (strcmp(result[0], "enable_jni_n2j_trace") == 0) {
                strcpy(enable_jni_n2j_trace, result[1]);
                enable_jni_n2j_trace[strlen(enable_jni_n2j_trace)-1] = 0;
            } else if (strcmp(result[0], "dex_class_name") == 0) {
                strcpy(dex_class_name, result[1]);
                dex_class_name[strlen(dex_class_name)-1] = 0;
            } else if (strcmp(result[0], "dex_method_name") == 0) {
                strcpy(dex_method_name, result[1]);
                dex_method_name[strlen(dex_method_name)-1] = 0;
            } else if (strcmp(result[0], "j2n_function_name") == 0) {
                strcpy(j2n_function_name, result[1]);
                j2n_function_name[strlen(j2n_function_name)-1] = 0;
            } else if (strcmp(result[0], "j2n_function_return_value") == 0) {
                strcpy(j2n_function_return_value, result[1]);
                j2n_function_return_value[strlen(j2n_function_return_value)-1] = 0;
            } else if (strcmp(result[0], "j2n_function_arg_index") == 0) {
                strcpy(j2n_function_arg_index, result[1]);
                j2n_function_arg_index[strlen(j2n_function_arg_index)-1] = 0;
            } else if (strcmp(result[0], "j2n_function_arg_length") == 0) {
                strcpy(j2n_function_arg_length, result[1]);
                j2n_function_arg_length[strlen(j2n_function_arg_length)-1] = 0;
            } else if (strcmp(result[0], "j2n_function_arg_value") == 0) {
                strcpy(j2n_function_arg_value, result[1]);
                j2n_function_arg_value[strlen(j2n_function_arg_value)-1] = 0;
            } else if (strcmp(result[0], "n2j_function_name") == 0) {
                strcpy(n2j_function_name, result[1]);
                n2j_function_name[strlen(n2j_function_name)-1] = 0;
            } else if (strcmp(result[0], "n2j_function_return_value") == 0) {
                strcpy(n2j_function_return_value, result[1]);
                n2j_function_return_value[strlen(n2j_function_return_value)-1] = 0;
            } else {
                
            }
        }

        fclose(fp);

    }

    free(result);
    return NULL;
}

/*
void* libcTraceInit(const char* symbol) {

    if (symbol == NULL) {
        ALOGI("analysisLog - libcTrace - no symbol defined in libcTraceInit().\n");
        return NULL;
    }

    void* handle = dlopen("/system/lib/libc.so", RTLD_LAZY);
    if (handle == NULL) {
        ALOGI("analysisLog - libcTrace - %s - dlopen libc failed.\n", symbol);
    } else {        
        void* reset_array = dlsym(handle, "reset_array");
        if (reset_array == NULL) {
            ALOGI("analysisLog - libcTrace - %s - no \"reset_array\" found in libc.\n", symbol);
        } else {
            reset_array_func array_func = (reset_array_func)reset_array;
            (*array_func) ();
        }
    }

    return NULL;
}
*/

void* libcTrace(const char* symbol) {

    if (symbol == NULL) {
        ALOGI("analysisLog - libcTrace - no symbol defined in libcTrace().\n");
        return NULL;
    }

    int id = getpid();

    char id_string[16];
    sprintf(id_string, "%d", id);

    void* handle = dlopen("/system/lib/libc.so", RTLD_LAZY);

    if (handle == NULL) {
        ALOGI("analysisLog - libcTrace - %s - dlopen libc failed.\n", symbol);
    } else {        
        void* set_pkg_name = dlsym(handle, "set_pkg_name");
        if (set_pkg_name == NULL) {
            ALOGI("analysisLog - libcTrace - %s - no \"set_pkg_name\" found in libc.\n", symbol);
        } else {
            set_pkg_name_func set_pkg_func = (set_pkg_name_func)set_pkg_name;
            (*set_pkg_func) (pkgname, id_string);
        }

        void* set_method_name = dlsym(handle, "set_method_name");
        if (set_method_name == NULL) {
            ALOGI("analysisLog - libcTrace - %s - no \"set_method_name\" found in libc.\n", symbol);
        } else {
            set_method_name_func set_method_func = (set_method_name_func)set_method_name;
            (*set_method_func) (symbol);
        }

        void* set_trace_id = dlsym(handle, "set_trace_id");
        if (set_trace_id == NULL) {
            ALOGI("analysisLog - libcTrace - %s - no \"set_trace_id\" found in libc.\n", symbol);
        } else {
            set_trace_id_func set_func = (set_trace_id_func)set_trace_id;
            (*set_func) (pkg_id);
        }

    }

    return NULL;
}

void* libcTraceStop(const char* symbol) {

    if (symbol == NULL) {
        ALOGI("analysisLog - libcTraceStop - no symbol defined in libcTraceStop().\n");
        return NULL;
    }

    void* handle = dlopen("/system/lib/libc.so", RTLD_LAZY);

    if (handle == NULL) {
        ALOGI("analysisLog - libcTraceStop - %s - dlopen libc failed.\n", symbol);
    } else {
        
        int* trace_id = (int *)dlsym(handle, "__trace_id");
        if (trace_id == NULL) {
            ALOGI("analysisLog - libcTraceStop - %s - no \"__trace_id\" found in libc.\n", symbol);
        } else {
            *trace_id = 100000;
        }

        void* reset_method_name = dlsym(handle, "reset_method_name");
        if (reset_method_name == NULL) {
            ALOGI("analysisLog - libcTrace - %s - no \"reset_method_name\" found in libc.\n", symbol);
        } else {
            reset_method_name_func reset_method_func = (reset_method_name_func)reset_method_name;
            (*reset_method_func) ();
        }
    }

    return NULL;
}

//=========================detection start=========================//
void* dexDetection(DexOrJar* pDexOrJar, DvmDex* pDvmDex, Object* loader)
{
    MemMapping* mem = &pDvmDex->memMap; // get the memory map of the dex file 
    int parseFlags = kDexParseDefault;
    DexFile* pDexFile = dexFileParse((u1*)mem->addr, mem->length, parseFlags);

    if (pDexFile == NULL) {
        ALOGI("analysisLog - dexDetection - DexFile = NULL.");
        return NULL;
    }

    ALOGI("analysisLog - dexDetection - pDexFile baseAddr = %p, fileSize = %d", pDexFile->baseAddr, pDexFile->pHeader->fileSize);
    
    //DexFile* pDexFile = pDvmDex->pDexFile;
    u4 num_class_defs = pDexFile->pHeader->classDefsSize;
    DexClassData* pDexClassData = NULL;

    char int_string[32];
    sprintf(int_string, "%d", num_class_defs);
    
    //ALOGI("\n\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF - detection - FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    ALOGI("analysisLog - dexDetection - fileName = %s, num_class_defs = %d", pDexOrJar->fileName, num_class_defs);

    FILE* fp = NULL;
    FILE* dexload = NULL;
    char d_writepath[255] = {0}; // the file path for writing all the detected class information 
    char dexloadpath[255] = {0}; // the file path for writing all loaded dex file name and corresponding number of classes
     
    strcpy(d_writepath, "/data/data/");
    strcat(d_writepath, pkgname);
    strcat(d_writepath, "/");

    strcpy(dexloadpath, d_writepath);
    strcat(dexloadpath, "dexloaded");
    
    dexload = fopen(dexloadpath, "ab");
    if (dexload != NULL) {
        fwrite(int_string, sizeof(char), strlen(int_string), dexload);
        fwrite("\t", sizeof(char), strlen("\t"), dexload);
        fwrite(pDexOrJar->fileName, sizeof(char), strlen(pDexOrJar->fileName), dexload);
        fwrite("\n", sizeof(char), strlen("\n"), dexload);
        fclose(dexload);
    } else {
        ALOGI("analysisLog - dexDetection - Cannot open file: %s.", dexloadpath);
    }

    char dexFileName[100] = {0};
    const char token[] = " ./-";
    char* str_fileName = pDexOrJar->fileName;
    char* pch = strtok(str_fileName, token);

    while (pch != NULL){
        strcat(dexFileName, pch);
        pch = strtok(NULL, token);
    }

    /* dump the dex directly from memory */
    char dexfppath[255] = {0};
    strcpy(dexfppath, "/data/data/");
    strcat(dexfppath, pkgname);
    strcat(dexfppath, "/");
    strcat(dexfppath, dexFileName);
    strcat(dexfppath, int_string);
    strcat(dexfppath, ".dex");
    FILE* dexfp = NULL;
    dexfp = fopen(dexfppath, "wb");
    if (dexfp != NULL) {
        fwrite((u1*)pDexFile->baseAddr, 1, pDexFile->pHeader->fileSize, dexfp);
        fclose(dexfp);
    } else {
        ALOGI("analysisLog - dexDetection - Cannot open file: %s.", dexfppath);
    }

    strcat(d_writepath, dexFileName);
    strcat(d_writepath, int_string);
    strcat(d_writepath, ".classdump");

    fp = fopen(d_writepath, "wb");

    if (fp != NULL) {
        for (u4 i = 0; i < num_class_defs; i++) {
            const DexClassDef* pClassDef = dexGetClassDef(pDexFile, i);
            //const char* class_sourceFile = dexGetSourceFile(pDexFile, pClassDef);
            const char* class_descriptor = dexGetClassDescriptor(pDexFile, pClassDef);
            //const char* superClass_description = dexGetSuperClassDescriptor(pDexFile, pClassDef);

            fwrite(class_descriptor, sizeof(char), strlen(class_descriptor), fp);
            fwrite("\n", sizeof(char), strlen("\n"), fp);

            //ALOGI("\n\nCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC - detection - CCCCCCCCCCCCCCCCCCCCCCCCCCCCCC");
            //ALOGI("detection - class_sourceFile = %s, class_descriptor = %s", class_sourceFile, class_descriptor);
            //ALOGI("detection - class_sourceFile = %s, class_descriptor = %s, superClass_description = %s", class_sourceFile, class_descriptor, superClass_description);

            const u1* pData = dexGetClassData(pDexFile, pClassDef);
            pDexClassData = dexReadAndVerifyClassData(&pData, NULL);

            if (pDexClassData->header.staticFieldsSize != 0) {
                //ALOGI("detection - staticFields - Size = %d", pDexClassData->header.staticFieldsSize);
                for (u4 i = 0; i < pDexClassData->header.staticFieldsSize; i++) {
                    
                    DexField* static_field = &(pDexClassData->staticFields[i]);
                    
                    const DexFieldId* static_fieldId = dexGetFieldId(pDexFile, static_field->fieldIdx);
                    const DexStringId* static_fieldStringId = dexGetStringId(pDexFile, static_fieldId->nameIdx);
                    const char* static_field_name = dexGetStringData(pDexFile, static_fieldStringId);
                    
                    const DexTypeId* static_fieldTypeId = dexGetTypeId(pDexFile, static_fieldId->typeIdx);
                    const DexStringId* static_fieldTypeStringId = dexGetStringId(pDexFile, static_fieldTypeId->descriptorIdx);
                    const char* static_field_type = dexGetStringData(pDexFile, static_fieldTypeStringId);

                    fwrite("\tstaticField: ", sizeof(char), strlen("\tstaticField: "), fp);
                    fwrite(static_field_name, sizeof(char), strlen(static_field_name), fp);
                    
                    fwrite("\ttype: ", sizeof(char), strlen("\ttype: "), fp);
                    fwrite(static_field_type, sizeof(char), strlen(static_field_type), fp);
                    
                    sprintf(int_string, "0x%04x", static_field->accessFlags);
                    fwrite("\taccessFlags: ", sizeof(char), strlen("\taccessFlags: "), fp);
                    fwrite(int_string, sizeof(char), strlen(int_string), fp);
                    
                    fwrite("\n", sizeof(char), strlen("\n"), fp);
                    
                    //ALOGI("analysisLog - detection - staticFields - name = %s, type = %s, accessFlags = 0x%04x", static_field_name, static_field_type, static_field->accessFlags);
                }
            }

            if (pDexClassData->header.instanceFieldsSize != 0) {
                //ALOGI("analysisLog - detection - instanceFields - Size = %d", pDexClassData->header.instanceFieldsSize);
                for (u4 i = 0; i < pDexClassData->header.instanceFieldsSize; i++) {
                    
                    DexField* instance_field = &(pDexClassData->instanceFields[i]);
                    
                    const DexFieldId* instance_fieldId = dexGetFieldId(pDexFile, instance_field->fieldIdx);
                    const DexStringId* instance_fieldStringId = dexGetStringId(pDexFile, instance_fieldId->nameIdx);
                    const char* instance_field_name = dexGetStringData(pDexFile, instance_fieldStringId);
                    
                    const DexTypeId* instance_fieldTypeId = dexGetTypeId(pDexFile, instance_fieldId->typeIdx);
                    const DexStringId* instance_fieldTypeStringId = dexGetStringId(pDexFile, instance_fieldTypeId->descriptorIdx);
                    const char* instance_field_type = dexGetStringData(pDexFile, instance_fieldTypeStringId);

                    fwrite("\tinstanceField: ", sizeof(char), strlen("\tinstanceField: "), fp);
                    fwrite(instance_field_name, sizeof(char), strlen(instance_field_name), fp);
                    
                    fwrite("\ttype: ", sizeof(char), strlen("\ttype: "), fp);
                    fwrite(instance_field_type, sizeof(char), strlen(instance_field_type), fp);
                    
                    sprintf(int_string, "0x%04x", instance_field->accessFlags);
                    fwrite("\taccessFlags: ", sizeof(char), strlen("\taccessFlags: "), fp);
                    fwrite(int_string, sizeof(char), strlen(int_string), fp);
                    
                    fwrite("\n", sizeof(char), strlen("\n"), fp);
                    
                    //ALOGI("analysisLog - detection - instanceFields - name = %s, type = %s, accessFlags = 0x%04x", instance_field_name, instance_field_type, instance_field->accessFlags);
                }
            }


            if (pDexClassData->header.directMethodsSize != 0) {
                //ALOGI("analysisLog - detection - directMethods - Size = %d", pDexClassData->header.directMethodsSize);
                for (u4 i = 0; i < pDexClassData->header.directMethodsSize; i++) {
                    
                    DexMethod* direct_method = &(pDexClassData->directMethods[i]);
                    
                    const DexMethodId* direct_dexMethodId = dexGetMethodId(pDexFile, direct_method->methodIdx);
                    const DexStringId* direct_nameStringId = dexGetStringId(pDexFile, direct_dexMethodId->nameIdx);
                    const char* direct_method_name = dexGetStringData(pDexFile, direct_nameStringId);
                    
                    const DexProtoId* direct_dexProtoId = dexGetProtoId(pDexFile, direct_dexMethodId->protoIdx);
                    const DexStringId* direct_shortStringId = dexGetStringId(pDexFile, direct_dexProtoId->shortyIdx);
                    const char* direct_method_proto = dexGetStringData(pDexFile, direct_shortStringId);
                    
                    const DexTypeId* direct_returnTypeId = dexGetTypeId(pDexFile, direct_dexProtoId->returnTypeIdx);
                    const DexStringId* direct_returnTypeStringId = dexGetStringId(pDexFile, direct_returnTypeId->descriptorIdx);
                    const char* direct_method_return_type = dexGetStringData(pDexFile, direct_returnTypeStringId);
                    const DexCode* direct_dexCode = dexGetCode(pDexFile, direct_method);

                    fwrite("\tdirectMethod: ", sizeof(char), strlen("\tdirectMethod: "), fp);
                    fwrite(direct_method_name, sizeof(char), strlen(direct_method_name), fp);

                    fwrite("\tprototype: ", sizeof(char), strlen("\tprototype: "), fp);
                    fwrite(direct_method_proto, sizeof(char), strlen(direct_method_proto), fp);

                    fwrite("\treturnType: ", sizeof(char), strlen("\treturnType: "), fp);
                    fwrite(direct_method_return_type, sizeof(char), strlen(direct_method_return_type), fp);

                    sprintf(int_string, "0x%04x", direct_method->accessFlags);
                    fwrite("\taccessFlags: ", sizeof(char), strlen("\taccessFlags: "), fp);
                    fwrite(int_string, sizeof(char), strlen(int_string), fp);
                    
                    if (direct_dexCode != NULL) {
                        //ALOGI("analysisLog - detection - directMethods - name = %s, prototype = %s, returnType = %s, accessFlags = 0x%04x, codeOffset = 0x%x, insns = %p, insnsSize = %d", direct_method_name, direct_method_proto, direct_method_return_type, direct_method->accessFlags, direct_method->codeOff, direct_dexCode->insns, direct_dexCode->insnsSize);

                        sprintf(int_string, "0x%x", direct_method->codeOff);
                        fwrite("\tcodeOffset: ", sizeof(char), strlen("\tcodeOffset: "), fp);
                        fwrite(int_string, sizeof(char), strlen(int_string), fp);

                        sprintf(int_string, "%p", direct_dexCode->insns);
                        fwrite("\tinsns: ", sizeof(char), strlen("\tinsns: "), fp);
                        fwrite(int_string, sizeof(char), strlen(int_string), fp);

                        sprintf(int_string, "%d", direct_dexCode->insnsSize);
                        fwrite("\tinsnsSize: ", sizeof(char), strlen("\tinsnsSize: "), fp);
                        fwrite(int_string, sizeof(char), strlen(int_string), fp);
                        
                        // dump the direct_method bytecode instruction
                        
                        if (dex_class_name[0] != 0 && dex_method_name[0] != 0) {
                            if (strstr(class_descriptor, dex_class_name) && strcmp(direct_method_name, dex_method_name) == 0) {

                                ALOGI("analysisLog - dexDetection - directMethods - name = %s, (from class: %s), insns = %p, insnsSize = %d", direct_method_name, class_descriptor, direct_dexCode->insns, direct_dexCode->insnsSize);

                                char codefppath[255] = {0};
                                strcpy(codefppath, "/data/data/");
                                strcat(codefppath, pkgname);
                                strcat(codefppath, "/");
                                strcat(codefppath, direct_method_name);
                                strcat(codefppath, ".dexcode");
                                FILE* codefp = NULL;
                                codefp = fopen(codefppath, "wb");
                                fwrite(direct_dexCode->insns, 2, direct_dexCode->insnsSize, codefp);
                                fclose(codefp);
                            }
                        }

                    } else {
                        //ALOGI("analysisLog - detection - native or abstract directMethods - name = %s, prototype = %s, returnType = %s, accessFlags = 0x%04x", direct_method_name, direct_method_proto, direct_method_return_type, direct_method->accessFlags);
                    }

                    fwrite("\n", sizeof(char), strlen("\n"), fp);

                    const DexTypeList* direct_paramList = dexGetProtoParameters(pDexFile, direct_dexProtoId);
                    if (direct_paramList != NULL) {
                        for (u4 i = 0; i < direct_paramList->size; i++) {
                            const DexTypeItem* direct_dexTypeItem = dexGetTypeItem(direct_paramList, i);
                            const char* direct_param_type = dexStringByTypeIdx(pDexFile, direct_dexTypeItem->typeIdx);

                            fwrite("\t\tparamType: ", sizeof(char), strlen("\t\tparamType: "), fp);
                            fwrite(direct_param_type, sizeof(char), strlen(direct_param_type), fp);
                            fwrite("\n", sizeof(char), strlen("\n"), fp);
                            
                            //ALOGI("analysisLog - detection - directMethods - paramType = %s", direct_param_type);
                        }
                    }
                }
            }
            
            if (pDexClassData->header.virtualMethodsSize != 0) {
                //ALOGI("analysisLog - detection - virtualMethods - Size = %d", pDexClassData->header.virtualMethodsSize);
                for (u4 i = 0; i < pDexClassData->header.virtualMethodsSize; i++) {
                    
                    DexMethod* virtual_method = &(pDexClassData->virtualMethods[i]);
                    
                    const DexMethodId* dexMethodId = dexGetMethodId(pDexFile, virtual_method->methodIdx);
                    const DexStringId* nameStringId = dexGetStringId(pDexFile, dexMethodId->nameIdx);
                    const char* virtual_method_name = dexGetStringData(pDexFile, nameStringId);

                    const DexProtoId* dexProtoId = dexGetProtoId(pDexFile, dexMethodId->protoIdx);
                    const DexStringId* shortStringId = dexGetStringId(pDexFile, dexProtoId->shortyIdx);
                    const char* virtual_method_proto = dexGetStringData(pDexFile, shortStringId);

                    const DexTypeId* returnTypeId = dexGetTypeId(pDexFile, dexProtoId->returnTypeIdx);
                    const DexStringId* returnTypeStringId = dexGetStringId(pDexFile, returnTypeId->descriptorIdx);
                    const char* virtual_method_return_type = dexGetStringData(pDexFile, returnTypeStringId);

                    const DexCode* virtual_dexCode = dexGetCode(pDexFile, virtual_method);

                    fwrite("\tvirtualMethod: ", sizeof(char), strlen("\tvirtualMethod: "), fp);
                    fwrite(virtual_method_name, sizeof(char), strlen(virtual_method_name), fp);

                    fwrite("\tprototype: ", sizeof(char), strlen("\tprototype: "), fp);
                    fwrite(virtual_method_proto, sizeof(char), strlen(virtual_method_proto), fp);

                    fwrite("\treturnType: ", sizeof(char), strlen("\treturnType: "), fp);
                    fwrite(virtual_method_return_type, sizeof(char), strlen(virtual_method_return_type), fp);

                    sprintf(int_string, "0x%04x", virtual_method->accessFlags);
                    fwrite("\taccessFlags: ", sizeof(char), strlen("\taccessFlags: "), fp);
                    fwrite(int_string, sizeof(char), strlen(int_string), fp);

                    if (virtual_dexCode != NULL) {
                        //ALOGI("analysisLog - detection - virtualMethods - name = %s, prototype = %s, returnType = %s, accessFlags = 0x%04x, codeOffset = 0x%x, insns = %p, insnsSize = %d", virtual_method_name, virtual_method_proto, virtual_method_return_type, virtual_method->accessFlags, virtual_method->codeOff, virtual_dexCode->insns, virtual_dexCode->insnsSize);

                        sprintf(int_string, "0x%x", virtual_method->codeOff);
                        fwrite("\tcodeOffset: ", sizeof(char), strlen("\tcodeOffset: "), fp);
                        fwrite(int_string, sizeof(char), strlen(int_string), fp);

                        sprintf(int_string, "%p", virtual_dexCode->insns);
                        fwrite("\tinsns: ", sizeof(char), strlen("\tinsns: "), fp);
                        fwrite(int_string, sizeof(char), strlen(int_string), fp);

                        sprintf(int_string, "%d", virtual_dexCode->insnsSize);
                        fwrite("\tinsnsSize: ", sizeof(char), strlen("\tinsnsSize: "), fp);
                        fwrite(int_string, sizeof(char), strlen(int_string), fp);

                        // dump the virtual_method bytecode instruction

                        if (dex_class_name[0] != 0 && dex_method_name[0] != 0) {
                            if (strstr(class_descriptor, dex_class_name) && strcmp(virtual_method_name, dex_method_name) == 0) {

                                ALOGI("analysisLog - dexDetection - virtualMethods - name = %s, (from class: %s), insns = %p, insnsSize = %d", virtual_method_name, class_descriptor, virtual_dexCode->insns, virtual_dexCode->insnsSize);

                                char codefppath[255] = {0};
                                strcpy(codefppath, "/data/data/");
                                strcat(codefppath, pkgname);
                                strcat(codefppath, "/");
                                strcat(codefppath, virtual_method_name);
                                strcat(codefppath, ".dexcode");
                                FILE* codefp = NULL;
                                codefp = fopen(codefppath, "wb");
                                fwrite(virtual_dexCode->insns, 2, virtual_dexCode->insnsSize, codefp);
                                fclose(codefp);
                            }
                        }

                    } else {
                        //ALOGI("analysisLog - detection - native or abstract virtualMethods - name = %s, prototype = %s, returnType = %s, accessFlags = 0x%04x", virtual_method_name, virtual_method_proto, virtual_method_return_type, virtual_method->accessFlags);
                    }

                    fwrite("\n", sizeof(char), strlen("\n"), fp);

                    const DexTypeList* paramList = dexGetProtoParameters(pDexFile, dexProtoId);
                    if (paramList != NULL) {
                        for (u4 i = 0; i < paramList->size; i++) {
                            const DexTypeItem* dexTypeItem = dexGetTypeItem(paramList, i);
                            const char* virtual_param_type = dexStringByTypeIdx(pDexFile, dexTypeItem->typeIdx);

                            fwrite("\t\tparamType: ", sizeof(char), strlen("\t\tparamType: "), fp);
                            fwrite(virtual_param_type, sizeof(char), strlen(virtual_param_type), fp);
                            fwrite("\n", sizeof(char), strlen("\n"), fp);
                            
                            //ALOGI("detection - virtualMethods - paramType = %s", virtual_param_type);
                        }
                    }
                }
            }
        }

        fclose(fp);
    } else {
        ALOGI("analysisLog - dexDetection - Cannot open file: %s.", d_writepath);
    }

    return NULL;  
}
//=========================detection end=========================//

/*
 * private static Class defineClassNative(String name, ClassLoader loader,
 *      int cookie)
 *
 * Load a class from a DEX file.  This is roughly equivalent to defineClass()
 * in a regular VM -- it's invoked by the class loader to cause the
 * creation of a specific class.  The difference is that the search for and
 * reading of the bytes is done within the VM.
 *
 * The class name is a "binary name", e.g. "java.lang.String".
 *
 * Returns a null pointer with no exception if the class was not found.
 * Throws an exception on other failures.
 */
static void Dalvik_dalvik_system_DexFile_defineClassNative(const u4* args,
    JValue* pResult)
{
    StringObject* nameObj = (StringObject*) args[0];
    Object* loader = (Object*) args[1];
    int cookie = args[2];
    ClassObject* clazz = NULL;
    DexOrJar* pDexOrJar = (DexOrJar*) cookie;
    DvmDex* pDvmDex;
    char* name;
    char* descriptor;

    name = dvmCreateCstrFromString(nameObj);
    descriptor = dvmDotToDescriptor(name);
    ALOGV("--- Explicit class load '%s' l=%p c=0x%08x",
        descriptor, loader, cookie);

    free(name);

    if (!validateCookie(cookie))
        RETURN_VOID();

    if (pDexOrJar->isDex)
        pDvmDex = dvmGetRawDexFileDex(pDexOrJar->pRawDexFile);
    else
        pDvmDex = dvmGetJarFileDex(pDexOrJar->pJarFile);

    /* once we load something, we can't unmap the storage */
    pDexOrJar->okayToFree = false;

    //=========================detection start=========================//

    int id = getuid();
    
    if (id) {
        if (config_readable) {
            pthread_mutex_lock(&config_read_mutex);
            if (config_readable) {
                config_readable = false;
                pthread_mutex_unlock(&config_read_mutex);
                pthread_t config_thread;
                pthread_create(&config_thread, NULL, read_config, NULL);
                
            }else{
                pthread_mutex_unlock(&config_read_mutex);
            }
        }
    }

    if (strcmp(pkgname,"")) {
        char* pkgnameIncluded = strstr(pDexOrJar->fileName, pkgname);
        if (pkgnameIncluded && d_flag) {
            d_flag = false;
            pkg_id = id;
        }  
    }

    if (pkg_id == id && strcmp(enable_class_detection, "true") == 0) {
        char* apkIncluded = strstr(pDexOrJar->fileName, ".apk");
        char* dexIncluded = strstr(pDexOrJar->fileName, ".dex");
        char* jarIncluded = strstr(pDexOrJar->fileName, ".jar");
        char* zipIncluded = strstr(pDexOrJar->fileName, ".zip");
        
        if (apkIncluded || dexIncluded || jarIncluded || zipIncluded) {
            dexDetection(pDexOrJar, pDvmDex, loader);
            /*
            if (strcmp(enable_lib_trace, "true") == 0 && l_flag) {
                libcTraceInit("libcTraceInit");
                l_flag = false;
            }
            */         
        }   
    }
    
    //=========================detection end=========================//

    clazz = dvmDefineClass(pDvmDex, descriptor, loader);
    Thread* self = dvmThreadSelf();
    if (dvmCheckException(self)) {
        /*
         * If we threw a "class not found" exception, stifle it, since the
         * contract in the higher method says we simply return null if
         * the class is not found.
         */
        Object* excep = dvmGetException(self);
        if (strcmp(excep->clazz->descriptor,
                   "Ljava/lang/ClassNotFoundException;") == 0 ||
            strcmp(excep->clazz->descriptor,
                   "Ljava/lang/NoClassDefFoundError;") == 0)
        {
            dvmClearException(self);
        }
        clazz = NULL;
    }

    free(descriptor);
    RETURN_PTR(clazz);
}

/*
 * private static String[] getClassNameList(int cookie)
 *
 * Returns a String array that holds the names of all classes in the
 * specified DEX file.
 */
static void Dalvik_dalvik_system_DexFile_getClassNameList(const u4* args,
    JValue* pResult)
{
    int cookie = args[0];
    DexOrJar* pDexOrJar = (DexOrJar*) cookie;
    Thread* self = dvmThreadSelf();

    if (!validateCookie(cookie))
        RETURN_VOID();

    DvmDex* pDvmDex;
    if (pDexOrJar->isDex)
        pDvmDex = dvmGetRawDexFileDex(pDexOrJar->pRawDexFile);
    else
        pDvmDex = dvmGetJarFileDex(pDexOrJar->pJarFile);
    assert(pDvmDex != NULL);
    DexFile* pDexFile = pDvmDex->pDexFile;

    int count = pDexFile->pHeader->classDefsSize;

    ClassObject* arrayClass =
        dvmFindArrayClassForElement(gDvm.classJavaLangString);
    ArrayObject* stringArray =
        dvmAllocArrayByClass(arrayClass, count, ALLOC_DEFAULT);
    if (stringArray == NULL) {
        /* probably OOM */
        ALOGD("Failed allocating array of %d strings", count);
        assert(dvmCheckException(self));
        RETURN_VOID();
    }

    int i;
    for (i = 0; i < count; i++) {
        const DexClassDef* pClassDef = dexGetClassDef(pDexFile, i);
        const char* descriptor =
            dexStringByTypeIdx(pDexFile, pClassDef->classIdx);

        char* className = dvmDescriptorToDot(descriptor);

        StringObject* str = dvmCreateStringFromCstr(className);
        dvmSetObjectArrayElement(stringArray, i, (Object *)str);
        dvmReleaseTrackedAlloc((Object *)str, self);
        free(className);
    }

    dvmReleaseTrackedAlloc((Object*)stringArray, self);
    RETURN_PTR(stringArray);
}

/*
 * public static boolean isDexOptNeeded(String fileName)
 *         throws FileNotFoundException, IOException
 *
 * Returns true if the VM believes that the apk/jar file is out of date
 * and should be passed through "dexopt" again.
 *
 * @param fileName the absolute path to the apk/jar file to examine.
 * @return true if dexopt should be called on the file, false otherwise.
 * @throws java.io.FileNotFoundException if fileName is not readable,
 *         not a file, or not present.
 * @throws java.io.IOException if fileName is not a valid apk/jar file or
 *         if problems occur while parsing it.
 * @throws java.lang.NullPointerException if fileName is null.
 * @throws dalvik.system.StaleDexCacheError if the optimized dex file
 *         is stale but exists on a read-only partition.
 */
static void Dalvik_dalvik_system_DexFile_isDexOptNeeded(const u4* args,
    JValue* pResult)
{
    StringObject* nameObj = (StringObject*) args[0];
    char* name;
    DexCacheStatus status;
    int result;

    name = dvmCreateCstrFromString(nameObj);
    if (name == NULL) {
        dvmThrowNullPointerException("fileName == null");
        RETURN_VOID();
    }
    if (access(name, R_OK) != 0) {
        dvmThrowFileNotFoundException(name);
        free(name);
        RETURN_VOID();
    }
    status = dvmDexCacheStatus(name);
    ALOGV("dvmDexCacheStatus(%s) returned %d", name, status);

    result = true;
    switch (status) {
    default: //FALLTHROUGH
    case DEX_CACHE_BAD_ARCHIVE:
        dvmThrowIOException(name);
        result = -1;
        break;
    case DEX_CACHE_OK:
        result = false;
        break;
    case DEX_CACHE_STALE:
        result = true;
        break;
    case DEX_CACHE_STALE_ODEX:
        dvmThrowStaleDexCacheError(name);
        result = -1;
        break;
    }
    free(name);

    if (result >= 0) {
        RETURN_BOOLEAN(result);
    } else {
        RETURN_VOID();
    }
}

const DalvikNativeMethod dvm_dalvik_system_DexFile[] = {
    { "openDexFileNative",  "(Ljava/lang/String;Ljava/lang/String;I)I",
        Dalvik_dalvik_system_DexFile_openDexFileNative },
    { "openDexFile",        "([B)I",
        Dalvik_dalvik_system_DexFile_openDexFile_bytearray },
    { "closeDexFile",       "(I)V",
        Dalvik_dalvik_system_DexFile_closeDexFile },
    { "defineClassNative",  "(Ljava/lang/String;Ljava/lang/ClassLoader;I)Ljava/lang/Class;",
        Dalvik_dalvik_system_DexFile_defineClassNative },
    { "getClassNameList",   "(I)[Ljava/lang/String;",
        Dalvik_dalvik_system_DexFile_getClassNameList },
    { "isDexOptNeeded",     "(Ljava/lang/String;)Z",
        Dalvik_dalvik_system_DexFile_isDexOptNeeded },
    { NULL, NULL, NULL },
};
