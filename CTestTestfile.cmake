# CMake generated Testfile for 
# Source directory: D:/Workspace/Certilife/ACME/GH
# Build directory: D:/Workspace/Certilife/ACME/GH
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test(acme_tests "D:/Workspace/Certilife/ACME/GH/Debug/test_acme_server.exe")
  set_tests_properties(acme_tests PROPERTIES  _BACKTRACE_TRIPLES "D:/Workspace/Certilife/ACME/GH/CMakeLists.txt;163;add_test;D:/Workspace/Certilife/ACME/GH/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test(acme_tests "D:/Workspace/Certilife/ACME/GH/Release/test_acme_server.exe")
  set_tests_properties(acme_tests PROPERTIES  _BACKTRACE_TRIPLES "D:/Workspace/Certilife/ACME/GH/CMakeLists.txt;163;add_test;D:/Workspace/Certilife/ACME/GH/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test(acme_tests "D:/Workspace/Certilife/ACME/GH/MinSizeRel/test_acme_server.exe")
  set_tests_properties(acme_tests PROPERTIES  _BACKTRACE_TRIPLES "D:/Workspace/Certilife/ACME/GH/CMakeLists.txt;163;add_test;D:/Workspace/Certilife/ACME/GH/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test(acme_tests "D:/Workspace/Certilife/ACME/GH/RelWithDebInfo/test_acme_server.exe")
  set_tests_properties(acme_tests PROPERTIES  _BACKTRACE_TRIPLES "D:/Workspace/Certilife/ACME/GH/CMakeLists.txt;163;add_test;D:/Workspace/Certilife/ACME/GH/CMakeLists.txt;0;")
else()
  add_test(acme_tests NOT_AVAILABLE)
endif()
