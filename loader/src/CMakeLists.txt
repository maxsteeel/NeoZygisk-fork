cmake_minimum_required(VERSION 3.22.1)
project("loader")

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_definitions(-DZKSU_VERSION=\"${ZKSU_VERSION}\")

set(CUSTOM_OUT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../build/out/${ANDROID_ABI}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CUSTOM_OUT_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CUSTOM_OUT_DIR}")

aux_source_directory(common COMMON_SRC_LIST)
add_library(common STATIC ${COMMON_SRC_LIST})
target_include_directories(common PRIVATE include)
target_include_directories(common PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../zygiskd/src/include)
target_link_options(common PRIVATE "-Wl,--exclude-libs,ALL")
target_link_libraries(common log)

aux_source_directory(injector INJECTOR_SRC_LIST)
add_library(zygisk SHARED ${INJECTOR_SRC_LIST})
target_include_directories(zygisk PRIVATE include)
target_include_directories(zygisk PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../zygiskd/src/include)
# target_compile_options(zygisk PRIVATE "-ffreestanding")
target_link_options(zygisk PRIVATE "-Wl,--exclude-libs,ALL -Wl,--pack-dyn-relocs=none")
target_link_options(zygisk PRIVATE "-nostartfiles")
target_link_libraries(zygisk log common lsplt_static)

aux_source_directory(ptracer PTRACER_SRC_LIST)
add_executable(libzygisk_ptrace.so ${PTRACER_SRC_LIST})
target_include_directories(libzygisk_ptrace.so PRIVATE include)
target_link_options(libzygisk_ptrace.so PRIVATE "-Wl,--exclude-libs,ALL")
target_link_libraries(libzygisk_ptrace.so log common)

set_target_properties(zygisk PROPERTIES NO_SONAME TRUE)
set_target_properties(libzygisk_ptrace.so PROPERTIES NO_SONAME TRUE)
add_subdirectory(external)
