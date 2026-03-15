cmake_minimum_required(VERSION 3.22.1)
project("zygiskd")

add_compile_definitions(
    ZKSU_VERSION=${ZKSU_VERSION}
    MIN_APATCH_VERSION=${MIN_APATCH_VERSION}
    MIN_KSU_VERSION=${MIN_KSU_VERSION}
    MAX_KSU_VERSION=${MAX_KSU_VERSION}
    MIN_MAGISK_VERSION=${MIN_MAGISK_VERSION}
)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../build/out/${ANDROID_ABI}")

aux_source_directory(. ZYGISKD_SRC_LIST)
aux_source_directory(root_impl ZYGISKD_SRC_LIST)

add_executable(zygiskd ${ZYGISKD_SRC_LIST})

# Since loader common is not exposed as a prefab, we just compile it into zygiskd
aux_source_directory(../../loader/src/common COMMON_SRC_LIST)
target_sources(zygiskd PRIVATE ${COMMON_SRC_LIST})

target_include_directories(zygiskd PRIVATE include)
target_include_directories(zygiskd PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../loader/src/include)
target_link_libraries(zygiskd log)

set_target_properties(zygiskd PROPERTIES NO_SONAME TRUE)
