cmake_minimum_required (VERSION 3.2 FATAL_ERROR)
project (tcmu-runner VERSION 0.9.1 LANGUAGES C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -std=c99")

# Red Hat has a nonstandard lib64 location.
if(EXISTS "/etc/redhat-release")
  set(tcmu-runner_HANDLER_PATH "/usr/lib64/tcmu-runner")
else()
  set(tcmu-runner_HANDLER_PATH "/usr/lib/tcmu-runner")
endif()


find_library(LIBNL_LIB nl-3)
find_library(LIBNL_GENL_LIB nl-genl-3)
set(LIBNL_LIBS
  ${LIBNL_LIB}
  ${LIBNL_GENL_LIB}
  )

find_path (LIBNL_INCLUDE_DIR
  NAMES
  netlink/netlink.h
  PATH_SUFFIXES
  libnl3
  )

find_package(ZLIB REQUIRED)
find_package(PkgConfig)
pkg_check_modules(GLIB REQUIRED gio-unix-2.0)

find_library(PTHREAD pthread)
find_library(DL dl)
find_library(KMOD kmod)
find_library(GFAPI gfapi)

# Stuff for building the main binary
add_executable(tcmu-runner
  main.c
  api.c
  tcmuhandler-generated.c
  )
target_compile_options(tcmu-runner
  PUBLIC -fPIC -Wl,-E
  )
target_include_directories(tcmu-runner
  PUBLIC ${PROJECT_BINARY_DIR}
  PUBLIC ${GLIB_INCLUDE_DIRS}
  PUBLIC ${LIBNL_INCLUDE_DIR}
  )
target_link_libraries(tcmu-runner
  ${LIBNL_LIB}
  ${LIBNL_GENL_LIB}
  ${GLIB_LIBRARIES}
  ${PTHREAD}
  ${DL}
  ${KMOD}
  )

add_custom_command(
  OUTPUT tcmuhandler-generated.c tcmuhandler-generated.h
  COMMAND gdbus-codegen tcmu-handler.xml --generate-c-code tcmuhandler-generated --c-generate-object-manager --interface-prefix org.kernel
  MAIN_DEPENDENCY tcmu-handler.xml
  )

# Stuff for building the file handler
add_library(handler_file
  SHARED
  file_example.c
  )
set_target_properties(handler_file
  PROPERTIES
  PREFIX ""
  )

# Stuff for building the glfs handler
add_library(handler_glfs
  SHARED
  glfs.c
  )
set_target_properties(handler_glfs
  PROPERTIES
  PREFIX ""
  )
target_link_libraries(handler_glfs
  ${GFAPI}
  )

# Stuff for building the qcow handler
add_library(handler_qcow
  SHARED
  qcow.c
  )
set_target_properties(handler_qcow
  PROPERTIES
  PREFIX ""
  )
target_link_libraries(handler_qcow
  ${ZLIB_LIBRARIES}
  )

# stamp out a header file to pass some of the CMake settings
# to the source code
configure_file (
  "${PROJECT_SOURCE_DIR}/version.h.in"
  "${PROJECT_BINARY_DIR}/version.h"
  )

