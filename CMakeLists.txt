cmake_minimum_required(VERSION 3.8)
project(metre)

set(CPACK_PACKAGE_CONTACT "dave.cridland@surevine.com")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "XMPP-S2S filtering and security proxy")
set(CPACK_PACKAGE_VERSION "0.0.1")
set(CPACK_RPM_PACKAGE_LICENSE "MIT")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Dave Cridland <dave.cridland@surevine.com>")

option(VENDORED_DEPS true)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")


# Pick package formats.
message(STATUS "Platform id is ${CMAKE_C_PLATFORM_ID}")
if (UNIX)
    set(CPACK_GENERATOR "TGZ")
    if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
        find_program(LSB_RELEASE lsb_release)
        execute_process(COMMAND ${LSB_RELEASE} -is OUTPUT_VARIABLE LSB_RELEASE_ID OUTPUT_STRIP_TRAILING_WHITESPACE)
        message(STATUS "Linux distro is ${LSB_RELEASE_ID}")
        if (${LSB_RELEASE_ID} MATCHES "Ubuntu")
            set(CPACK_GENERATOR "${CPACK_GENERATOR};DEB")
        endif (${LSB_RELEASE_ID} MATCHES "Ubuntu")
        if (${LSB_RELEASE_ID} MATCHES "CentOS")
            set(CPACK_GENERATOR "${CPACK_GENERATOR};RPM")
        endif (${LSB_RELEASE_ID} MATCHES "CentOS")
        if (${LSB_RELEASE_ID} MATCHES "RedHatEnterpriseServer")
            set(CPACK_GENERATOR "${CPACK_GENERATOR};RPM")
        endif (${LSB_RELEASE_ID} MATCHES "RedHatEnterpriseServer")
    endif (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
endif (UNIX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_definitions(-DSIGSLOT_COROUTINES)

if(UNIX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -pedantic -O0 -g -fcoroutines-ts -stdlib=libc++")
    add_definitions(-DMETRE_UNIX)
else()
    add_definitions(-DMETRE_WINDOWS)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /await")
endif ()

set(SIGSLOT_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/deps/sigslot")
set(RAPIDXML_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/deps/rapidxml")

set(BUILD_SHARED_LIBS OFF)
if (UNIX)
    add_subdirectory(deps/spiffing EXCLUDE_FROM_ALL)
    set(SPIFFING_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/deps/spiffing/include")
    set(SPIFFING_STATIC_LDFLAGS spiffing spiffing-asn)
endif(UNIX)

if(VENDORED_DEPS)
    find_path(_ICU2_INCLUDE_DIR PATHS /usr/local/opt/icu4c/include NAMES unicode/unorm2.h)
    find_path(_ICU_INCLUDE_DIR PATHS /usr/local/opt/icu4c/include NAMES unicode/unorm.h)
    message("ICU2 dir is ${ICU2_INCLUDE_DIR}")
    message("ICU dir is ${ICU_INCLUDE_DIR}")
    if (_ICU2_INCLUDE_DIR)
        add_definitions(-DHAVE_ICU2)
        #include_directories(${_ICU2_INCLUDE_DIR})
        #link_directories(${_ICU2_INCLUDE_DIR}/../lib)
        message("Found ICU2")
        set(ICU_LDFLAGS icudata icuuc)
    elseif (_ICU_INCLUDE_DIR)
        add_definitions(-DHAVE_ICU)
        #include_directories(${_ICU_INCLUDE_DIR})
        #link_directories(${_ICU_INCLUDE_DIR}/../lib)
        message("Found ICU")
        set(ICU_LDFLAGS icudata icuuc)
    else ()
        message("No ICU Found")
    endif ()

    set(gtest_force_shared_crt ON)

    set(OPENSSL_USE_STATIC_LIBS true)
    set(OPENSSL_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/deps/openssl)

    set(EVENT__LIBRARY_TYPE STATIC CACHE STRING "Build libevent statically" FORCE)
    add_subdirectory(deps/libevent EXCLUDE_FROM_ALL)
    add_subdirectory(deps/unbound EXCLUDE_FROM_ALL)
    add_subdirectory(deps/spdlog EXCLUDE_FROM_ALL)
    add_subdirectory(deps/googletest EXCLUDE_FROM_ALL)

    set(EVENT_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/deps/libevent/include" ${CMAKE_CURRENT_BINARY_DIR}/deps/libevent/include)
    set(EVENT_LDFLAGS event_core_static event_openssl_static event_extra_static)
    
    set(UNBOUND_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/deps/unbound/libunbound")
    set(UNBOUND_LDFLAGS unbound)

    set(SPDLOG_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/deps/spdlog/include")

    set(GTEST_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/deps/googletest/googletest/include")
    set(GTEST_BOTH_LIBRARIES gtest gtest_main)
else()
    # Find libs with pkg-config
    find_package(PkgConfig)
    pkg_check_modules(SPDLOG spdlog REQUIRED)
    set(SPDLOG_INCLUDE_DIRS "/usr/include/spdlog/") # Busted pkg-config file above
    pkg_check_modules(EVENT libevent libevent_openssl libevent_pthreads REQUIRED)
    pkg_check_modules(UNBOUND libunbound REQUIRED)
    pkg_check_modules(ICU icu-uc REQUIRED)
    add_definitions(-DHAVE_ICU)

    find_package(GMock REQUIRED)
endif()

find_package(OpenSSL REQUIRED)

set(FILTER_SOURCES
    src/filters/disco-filter.cc
    src/filters/disco-cache.cc
    src/filters/domain-translation.cc)
if (UNIX)
    list(APPEND FILTER_SOURCES src/filters/spiffing.cc)
endif()

if (ICU2_INCLUDE_DIR)
    list(APPEND FILTER_SOURCES src/filters/unicode.cc)
endif()

# Main sources
set(SOURCE_FILES
    ${FILTER_SOURCES}
    include/base64.h
    include/config.h
    include/defs.h
    include/dns.h
    include/feature.h
    include/filter.h
    include/jid.h
    include/log.h
    include/netsession.h
    include/router.h
    include/stanza.h
    include/xmlstream.h
    include/xmppexcept.h
    gen/dh1024.cc
    gen/dh2048.cc
    gen/dh4096.cc
    src/base64.cc
    src/components.cc
    src/config.cc
    src/dialback.cc
    src/feature.cc
    src/filter.cc
    src/jabberserver.cc
    src/jid.cc
    src/log.cc
    src/mainloop.cc
    src/netsession.cc
    src/router.cc
    src/stanza.cc
    src/starttls.cc src/bidi.cc
    src/xmlstream.cc src/saslexternal.cc include/dhparams.h include/http.h src/http.cc include/tls.h)

# Capabilities
set(CAPABILITY_SOURCES
    src/capabilities/pubsub.cc
    src/pubsub/pubsub.cc
    include/capability.h
    src/capability.cc
    src/capabilities/ping.cc
    include/endpoint.h
    src/endpoint.cc
    src/endpoints/simple.cc
    include/datastore.h
    src/datastore.cc
    include/sql.h
    include/node.h
    src/capabilities/node.cc
    src/capabilities/disco.cc
    src/capabilities/version.cc
)
set(SOURCE_FILES ${SOURCE_FILES} ${CAPABILITY_SOURCES})

if(UNIX)
    list(APPEND SOURCE_FILES src/linuxmain.cc)
else()
    list(APPEND SOURCE_FILES src/winmain.cc)
endif()

add_executable(metre ${SOURCE_FILES})

target_include_directories(metre PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    ${EVENT_INCLUDE_DIRS}
    ${ICU_INCLUDE_DIRS}
    ${RAPIDXML_INCLUDE_DIRS}
    ${SIGSLOT_INCLUDE_DIRS}
    ${SPDLOG_INCLUDE_DIRS}
    ${UNBOUND_INCLUDE_DIRS}
)

target_link_libraries(metre PRIVATE
    ${EVENT_LDFLAGS}
    ${ICU_LDFLAGS}
    ${RAPIDXML_LDFLAGS}
    ${SIGSLOT_LDFLAGS}
    ${SPDLOG_LDFLAGS}
    ${UNBOUND_LDFLAGS}
    OpenSSL::SSL
    OpenSSL::Crypto
)

if (UNIX)
    target_include_directories(metre PRIVATE
        ${SPIFFING_INCLUDE_DIRS}
    )

    set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
    set(THREADS_PREFER_PTHREAD_FLAG TRUE)
    find_package(Threads)

    target_link_libraries(metre PRIVATE
        ${SPIFFING_LDFLAGS}
        ${CMAKE_DL_LIBS} 
        Threads::Threads
    )
else()
    target_link_libraries(metre PRIVATE
        ws2_32
        crypt32
        Iphlpapi
    )
endif()

install(TARGETS metre DESTINATION bin)




enable_testing()

add_executable(metre-test
    tests/log.cc
    src/stanza.cc
    src/jid.cc
    tests/stanza.cc
    tests/jid.cc 
    ${CAPABILITY_SOURCES}
    tests/endpoint.cc
)

target_compile_definitions(metre-test PUBLIC
    METRE_TESTING=1
)

# These are all duplicated, because we're not actually linking against a 'libmetre', like we should

target_include_directories(metre-test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    ${EVENT_INCLUDE_DIRS}
    ${GTEST_INCLUDE_DIRS}
    ${ICU_INCLUDE_DIRS}
    ${RAPIDXML_INCLUDE_DIRS}
    ${SIGSLOT_INCLUDE_DIRS}
    ${SPDLOG_INCLUDE_DIRS}
    ${UNBOUND_INCLUDE_DIRS}
)

target_link_libraries(metre-test PRIVATE
    ${GTEST_BOTH_LIBRARIES}
    ${EVENT_LDFLAGS}
    ${ICU_LDFLAGS}
    ${RAPIDXML_LDFLAGS}
    ${SIGSLOT_LDFLAGS}
    ${SPDLOG_LDFLAGS}
    ${UNBOUND_LDFLAGS}
    OpenSSL::SSL
    OpenSSL::Crypto
)

if (UNIX)
    target_include_directories(metre-test PRIVATE
        ${SPIFFING_INCLUDE_DIRS}
    )

    target_link_libraries(metre-test PRIVATE
        ${SPIFFING_LDFLAGS}
        ${CMAKE_DL_LIBS} 
        Threads::Threads
    )
else()
    target_link_libraries(metre-test PRIVATE
        ws2_32
        crypt32
        Iphlpapi
    )

    target_link_options(metre-test PRIVATE
        /NODEFAULTLIB:LIBCPMTD
        /NODEFAULTLIB:LIBCMTD
    )
endif()

add_test(metre-test metre-test)


## These install into stupid places:
##
## install(FILES metre.conf.xml DESTINATION ./etc/metre)
## install(FILES data/README.md DESTINATION ./var/cache/metre)

include(CPack)
