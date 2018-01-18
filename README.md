# Introduction
This is an automatic analysis framework that provides a comprehensive view of packed Android applications' behaviors by conducing multi-level monitoring and information flow tracking. 

* Bytecode level analysis: instrument the Dalvik Virtual Machine (DVM) to extract the hidden class information during the app’s execution, and then reassemble the original DEX files.

* Native code level analysis: monitoring the execution of native components in packed Android apps, which can be used to reveal the behavior of packer. This dynamic monitoring analysis includes system call monitoring, Native-to-Java communication monitoring through JNI trace, library call monitoring (libc trace), IPC transcation through Binder, etc.


## File Description

This is the modified source code for Android Kitkat 4.4.3_r1. The source code folders are the following:

```
* binder -> <your_android_source_root>/frameworks/native/libs/binder
* bionic -> <your_android_source_root>/bionic
* dalvik -> <your_android_source_root>/dalvik
```

"analysis.sh" generates a "config" file that will be pushed to your Android device.

