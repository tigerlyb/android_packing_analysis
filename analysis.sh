#!/bin/bash

echo -e "\n***** File: $1"

package=$(aapt dump badging "$*" | awk '/package:/{gsub("name=|'"'"'","");  print $2}')
activity=$(aapt dump badging "$*" | awk '/launchable-activity:/{gsub("name=|'"'"'","");  print $2}')

if [[ -z "$package" ]]; then
    echo -e "***** No package name found\n\n."
else
    echo "***** Package: $package"
    echo "***** Launchable-activity: $activity"

    mkdir -p "./$package"
    
    # *************************************************************** #
    ### generate a configurate file to control the analysis process ###
    # *************************************************************** #
    echo -e "pkgname=$package\n" > "./$package/config"

    # enable class loading detection, set to true by default
    echo -e "enable_class_detection=true\n" >> "./$package/config"

    # enable Java method trace
    echo -e "enable_java_method_trace=false\n" >> "./$package/config"

    # enable libc trace
    echo -e "enable_lib_trace=true\n" >> "./$package/config"

    # enable Java-to-Native trace
    echo -e "enable_jni_j2n_trace=true\n" >> "./$package/config"

    # enable Java-to-Native trace for specific native method
    echo -e "j2n_function_name=\n" >> "./$package/config"

    # force change the return value of the native method
    echo -e "j2n_function_return_value=\n" >> "./$package/config"

    # force change the arg value of the native method
    echo -e "j2n_function_arg_index=\n" >> "./$package/config"
    echo -e "j2n_function_arg_length=\n" >> "./$package/config"
    echo -e "j2n_function_arg_value=\n" >> "./$package/config"

    # enable Native-to-Jave trace
    echo -e "enable_jni_n2j_trace=false\n" >> "./$package/config"

    # force change the return value of Java method
    echo -e "n2j_function_name=\n" >> "./$package/config"
    echo -e "n2j_function_return_value=\n" >> "./$package/config"
    # ************************************************************** #
    

    # dynamic analysis
    echo -e "\n***** push configurate file to device and start analysis..."
    adb push ./$package/config /data/
    install_status=$(adb install -r $1)

    # enable binder trace
    #uid=$(adb shell dumpsys package $package | grep userId= | awk '{gsub("userId=|'"'"'",""); print $1}')
    #echo -e "\n***** App uid: $uid"
    #echo "$uid" > "./$package/bindertrace"
    #echo "$package" >> "./$package/bindertrace"
    #adb push ./$package/bindertrace /data/
    
    if [[ "$install_status" != *"Failure"* ]]; then
        adb shell am start -n $package/$activity
    else
        echo -e "\n***** App installation Failed.\n"
    fi  

    
fi
