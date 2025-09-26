cmake_minimum_required(VERSION 3.12)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/../cmake) # main (top) cmake dir
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake) # project specific cmake dir

project("softvector" LANGUAGES CXX)

set(VERSION "1.0")

add_subdirectory(softfloat)

set(LIB_HEADERS src/fp_functions.h src/vector_functions.h src/crypto_util.h)
set(VECTOR
    src/vector_functions.cpp
)
set(FLOATING
    src/fp_functions.cpp
)
set(CRYPTO
    src/crypto_util.cpp
)
set(LIB_SOURCES ${VECTOR} ${FLOATING} ${CRYPTO})

add_library(softvector STATIC ${LIB_SOURCES})

target_include_directories(softvector PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(softvector PUBLIC softfloat)
set_target_properties(softvector PROPERTIES
    VERSION ${VERSION}
    FRAMEWORK FALSE
    PUBLIC_HEADER "${LIB_HEADERS}"
)

install(TARGETS softvector
    EXPORT ${PROJECT_NAME}Targets # for downstream dependencies
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/static COMPONENT libs # static lib
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT libs # shared lib
    FRAMEWORK DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT libs # for mac
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} COMPONENT devel # headers for mac (note the different component -> different package)
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} # headers
)
