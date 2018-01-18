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
 * All-inclusive internal header file.  Include this to get everything useful.
 */
#ifndef DALVIK_DALVIK_H_
#define DALVIK_DALVIK_H_

//=========================instrumentation code start=========================//
#include <fcntl.h>
#include <unistd.h>

#define ARRAY_SIZE 100000
typedef int (*set_trace_id_func) (int);
typedef int (*set_pkg_name_func) (char*, char*);
typedef int (*set_method_name_func) (const char*);
typedef int (*reset_method_name_func) ();

//typedef int (*get_trace_id_func) ();
//typedef int (*reset_array_func) ();

extern int pkg_id;  
extern char pkgname[100];

extern char enable_class_detection[10];
extern char enable_java_method_trace[10];
extern char enable_lib_trace[10];

extern char dex_class_name[100];
extern char dex_method_name[100];

extern char enable_jni_j2n_trace[10];
extern char enable_jni_n2j_trace[10];

extern char j2n_function_name[100];
extern char j2n_function_arg_index[10];
extern char j2n_function_arg_length[10];
extern char j2n_function_arg_value[ARRAY_SIZE];
extern char j2n_function_return_value[ARRAY_SIZE];
extern char n2j_function_name[100];
extern char n2j_function_return_value[ARRAY_SIZE];

extern void* libcTrace(const char*);
extern void* libcTraceStop(const char*);
//=========================instrumentation code end=========================//

#include "Common.h"
#include "Inlines.h"
#include "Misc.h"
#include "Bits.h"
#include "BitVector.h"
#include "libdex/SysUtil.h"
#include "libdex/DexDebugInfo.h"
#include "libdex/DexFile.h"
#include "libdex/DexProto.h"
#include "libdex/DexUtf.h"
#include "libdex/ZipArchive.h"
#include "DvmDex.h"
#include "RawDexFile.h"
#include "Sync.h"
#include "oo/Object.h"
#include "Native.h"
#include "native/InternalNative.h"

#include "DalvikVersion.h"
#include "Debugger.h"
#include "Profile.h"
#include "UtfString.h"
#include "Intern.h"
#include "ReferenceTable.h"
#include "IndirectRefTable.h"
#include "AtomicCache.h"
#include "Thread.h"
#include "Ddm.h"
#include "Hash.h"
#include "interp/Stack.h"
#include "oo/Class.h"
#include "oo/Resolve.h"
#include "oo/Array.h"
#include "Exception.h"
#include "alloc/Alloc.h"
#include "alloc/CardTable.h"
#include "alloc/HeapDebug.h"
#include "alloc/WriteBarrier.h"
#include "oo/AccessCheck.h"
#include "JarFile.h"
#include "jdwp/Jdwp.h"
#include "SignalCatcher.h"
#include "StdioConverter.h"
#include "JniInternal.h"
#include "LinearAlloc.h"
#include "analysis/DexVerify.h"
#include "analysis/DexPrepare.h"
#include "analysis/RegisterMap.h"
#include "Init.h"
#include "libdex/DexOpcodes.h"
#include "libdex/InstrUtils.h"
#include "AllocTracker.h"
#include "PointerSet.h"
#if defined(WITH_JIT)
#include "compiler/Compiler.h"
#endif
#include "Globals.h"
#include "reflect/Reflect.h"
#include "oo/TypeCheck.h"
#include "Atomic.h"
#include "interp/Interp.h"
#include "InlineNative.h"
#include "oo/ObjectInlines.h"

#endif  // DALVIK_DALVIK_H_
