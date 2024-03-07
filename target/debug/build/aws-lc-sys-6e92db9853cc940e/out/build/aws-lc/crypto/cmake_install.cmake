# Install script for directory: /home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/crypto

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/home/helkoulak/Documents/r-tcpls-v-0-1/target/debug/build/aws-lc-sys-6e92db9853cc940e/out")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "debug")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "/home/helkoulak/Documents/r-tcpls-v-0-1/target/debug/build/aws-lc-sys-6e92db9853cc940e/out/build/artifacts/libaws_lc_0_13_2_crypto.a")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xDevelopmentx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/crypto/cmake" TYPE FILE FILES "/home/helkoulak/Documents/r-tcpls-v-0-1/target/debug/build/aws-lc-sys-6e92db9853cc940e/out/build/aws-lc/crypto/crypto-config.cmake")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xDevelopmentx" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/crypto/cmake/static/crypto-targets.cmake")
    file(DIFFERENT EXPORT_FILE_CHANGED FILES
         "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/crypto/cmake/static/crypto-targets.cmake"
         "/home/helkoulak/Documents/r-tcpls-v-0-1/target/debug/build/aws-lc-sys-6e92db9853cc940e/out/build/aws-lc/crypto/CMakeFiles/Export/lib/crypto/cmake/static/crypto-targets.cmake")
    if(EXPORT_FILE_CHANGED)
      file(GLOB OLD_CONFIG_FILES "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/crypto/cmake/static/crypto-targets-*.cmake")
      if(OLD_CONFIG_FILES)
        message(STATUS "Old export file \"$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/crypto/cmake/static/crypto-targets.cmake\" will be replaced.  Removing files [${OLD_CONFIG_FILES}].")
        file(REMOVE ${OLD_CONFIG_FILES})
      endif()
    endif()
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/crypto/cmake/static" TYPE FILE FILES "/home/helkoulak/Documents/r-tcpls-v-0-1/target/debug/build/aws-lc-sys-6e92db9853cc940e/out/build/aws-lc/crypto/CMakeFiles/Export/lib/crypto/cmake/static/crypto-targets.cmake")
  if("${CMAKE_INSTALL_CONFIG_NAME}" MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/crypto/cmake/static" TYPE FILE FILES "/home/helkoulak/Documents/r-tcpls-v-0-1/target/debug/build/aws-lc-sys-6e92db9853cc940e/out/build/aws-lc/crypto/CMakeFiles/Export/lib/crypto/cmake/static/crypto-targets-debug.cmake")
  endif()
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/home/helkoulak/Documents/r-tcpls-v-0-1/target/debug/build/aws-lc-sys-6e92db9853cc940e/out/build/aws-lc/crypto/fipsmodule/cmake_install.cmake")

endif()

