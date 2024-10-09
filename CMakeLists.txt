cmake_minimum_required(VERSION 3.10)
project(sprd_signature LANGUAGES C CXX)

# build ssl and crypto
set(WITH_APPS OFF CACHE BOOL "Build applications" FORCE)
add_subdirectory(openssl-cmake)

#find_package(OpenSSL REQUIRED)

option(VB2048 "define vbmeta use 2048" OFF)
option(STATIC_LINK "link executable static" ON)

if (STATIC_LINK)
    set(CMAKE_EXE_LINKER_FLAGS "-static" )
endif ()

if (EMSCRIPTEN)
    message("Emscripten Spec")
    set(CMAKE_EXE_LINKER_FLAGS "-sFORCE_FILESYSTEM -sALLOW_MEMORY_GROWTH=1 -lproxyfs.js -lidbfs.js -sWASM=1 -sMODULARIZE=1 -sEXPORTED_RUNTIME_METHODS=\"['FS','PROXYFS','out','err','ccall','cwrap','setValue','getValue','UTF8ToString','UTF8ArrayToString','stringToUTF8Array','FS_createPath','FS_createDataFile','removeRunDependency','addRunDependency','addFunction','safeSetTimeout','runtimeKeepalivePush','runtimeKeepalivePop','maybeExit','wasmMemory','wasmExports','callMain']\"")
    set(OUTPUT_DIR ${CMAKE_BINARY_DIR}/dist/legacy)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${OUTPUT_DIR})
endif ()

# sprd_sign
file(GLOB_RECURSE sprd_sign_src "sprd_sign/*.c")
add_executable(sprd_sign ${sprd_sign_src})
if (VB2048)
    target_compile_definitions(sprd_sign PRIVATE "VBMETA_USE_2048=1")
else ()
    target_compile_definitions(sprd_sign PRIVATE "VBMETA_USE_2048=0")
endif ()
target_compile_options(sprd_sign PRIVATE "-Wall" "-Wextra" "-Wno-unused")
target_include_directories(sprd_sign PRIVATE 
    "sprd_sign/common/pk1/inc"
    "sprd_sign/common/rsa/inc"
    "sprd_sign/common/sha256/inc"
    "sprd_sign/common/verify/inc"
)
target_link_libraries(sprd_sign crypto)

# get-raw-image
add_executable(get-raw-image "get-raw-image.c")

# imgheaderinsert
file(GLOB_RECURSE imgheaderinsert_src "insertheader/*.c")
add_executable(imgheaderinsert ${imgheaderinsert_src})

file(GLOB_RECURSE generate_sign_script_for_vbmeta_src "sign_vbmeta/*.c")
add_executable(generate_sign_script_for_vbmeta ${generate_sign_script_for_vbmeta_src})

if (EMSCRIPTEN) # Define export name on emscripten
    target_link_options(sprd_sign PRIVATE "-sEXPORT_NAME=sprd_sign")
    # target add resource keys
    target_link_options(sprd_sign PRIVATE "--preload-file=${CMAKE_CURRENT_SOURCE_DIR}/config@/resource") # will add to /recource

    target_link_options(get-raw-image PRIVATE "-sEXPORT_NAME=get_raw_image")
    target_link_options(imgheaderinsert PRIVATE "-sEXPORT_NAME=imgheaderinsert")

    # unusable on web platform
    #target_link_options(imgheaderinsert PRIVATE "-sEXPORT_NAME=enerate_sign_script_for_vbmeta")

    # 获取 web 目录中的所有文件
    set(WEB_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/web")
    file(GLOB_RECURSE WEB_FILES "${WEB_SOURCE_DIR}/*")
    foreach(file_path ${WEB_FILES})
        # 计算相对路径
        file(RELATIVE_PATH rel_path "${WEB_SOURCE_DIR}" "${file_path}")
        # 定义目标路径
        set(dest_path "${CMAKE_BINARY_DIR}/dist/${rel_path}")
        # 如果是目录，则创建目录
        if(IS_DIRECTORY "${file_path}")
            file(MAKE_DIRECTORY "${dest_path}")
        else()
            configure_file("${file_path}" "${dest_path}" COPYONLY)
        endif()
    endforeach()
endif ()