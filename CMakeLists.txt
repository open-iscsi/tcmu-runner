cmake_minimum_required (VERSION 3.0 FATAL_ERROR)
project (tcmu-runner VERSION 1.0.3 LANGUAGES C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -std=c99")

include(GNUInstallDirs)

set(tcmu-runner_HANDLER_PATH "${CMAKE_INSTALL_LIBDIR}/tcmu-runner")

option(with-glfs "build Gluster glfs handler" true)
option(with-qcow "build qcow handler" true)

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

find_package(PkgConfig)
pkg_check_modules(GLIB REQUIRED gio-unix-2.0)
pkg_check_modules(KMOD REQUIRED libkmod)

find_library(PTHREAD pthread)
find_library(DL dl)

# Stuff for building the shared library
add_library(tcmu
  SHARED
  api.c
  libtcmu.c
  )
set_target_properties(tcmu
  PROPERTIES
  SOVERSION "1"
  )
target_include_directories(tcmu
  PUBLIC ${LIBNL_INCLUDE_DIR}
  )
target_link_libraries(tcmu
  ${LIBNL_LIB}
  ${LIBNL_GENL_LIB}
  )
install(TARGETS tcmu LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

# Stuff for building the static library
add_library(tcmu_static
  api.c
  libtcmu.c
  )
target_include_directories(tcmu_static
  PUBLIC ${LIBNL_INCLUDE_DIR}
  )

# Stuff for building the main binary
add_executable(tcmu-runner
  main.c
  tcmuhandler-generated.c
  )
target_link_libraries(tcmu-runner tcmu)
target_include_directories(tcmu-runner
  PUBLIC ${PROJECT_BINARY_DIR}
  PUBLIC ${GLIB_INCLUDE_DIRS}
  PUBLIC ${KMOD_INCLUDE_DIRS}
  )
target_link_libraries(tcmu-runner
  ${GLIB_LIBRARIES}
  ${PTHREAD}
  ${DL}
  ${KMOD_LIBRARIES}
  -Wl,--no-export-dynamic
  -Wl,--dynamic-list=${CMAKE_SOURCE_DIR}/main-syms.txt
  )
install(TARGETS tcmu-runner RUNTIME DESTINATION bin)

add_custom_command(
  OUTPUT tcmuhandler-generated.c tcmuhandler-generated.h
  COMMAND gdbus-codegen ${CMAKE_SOURCE_DIR}/tcmu-handler.xml --generate-c-code tcmuhandler-generated --c-generate-object-manager --interface-prefix org.kernel
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

# Stuff for building the async file handler
add_library(handler_file_async
  SHARED
  file_example.c
  )
set_target_properties(handler_file_async
  PROPERTIES
  PREFIX ""
  COMPILE_FLAGS "-DASYNC_FILE_HANDLER"
  )
target_link_libraries(handler_file_async ${PTHREAD})

# The minimal library consumer
add_executable(consumer
  consumer.c
  )
target_link_libraries(consumer tcmu)

if (with-glfs)
	find_library(GFAPI gfapi)

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
	install(TARGETS handler_glfs DESTINATION ${CMAKE_INSTALL_LIBDIR}/tcmu-runner)
endif (with-glfs)

if (with-qcow)
	find_package(ZLIB REQUIRED)

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
	install(TARGETS handler_qcow DESTINATION ${CMAKE_INSTALL_LIBDIR}/tcmu-runner)
endif (with-qcow)

# stamp out a header file to pass some of the CMake settings
# to the source code
configure_file (
  "${PROJECT_SOURCE_DIR}/version.h.in"
  "${PROJECT_BINARY_DIR}/version.h"
  )


install(FILES libtcmu.h libtcmu_common.h
  DESTINATION include)
install(FILES org.kernel.TCMUService1.service
  DESTINATION /usr/share/dbus-1/system-services)
install(FILES tcmu-runner.conf DESTINATION /etc/dbus-1/system.d)
if (SUPPORT_SYSTEMD)
  install(FILES tcmu-runner.service DESTINATION /usr/lib/systemd/system/)
endif (SUPPORT_SYSTEMD)

