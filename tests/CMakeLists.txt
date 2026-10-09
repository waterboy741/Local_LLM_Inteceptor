find_package(Qt6 REQUIRED COMPONENTS Test)

qt_add_executable(m1_foundation_tests M1FoundationTests.cpp)
target_link_libraries(m1_foundation_tests PRIVATE interceptor_gui Qt6::Test)
add_test(NAME m1_foundation COMMAND m1_foundation_tests)
set_tests_properties(m1_foundation PROPERTIES
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
    TIMEOUT 30
)

qt_add_executable(m2_proxy_tests M2ProxyTests.cpp)
target_link_libraries(m2_proxy_tests PRIVATE interceptor_proxy Qt6::Test)
add_test(NAME m2_proxy COMMAND m2_proxy_tests)
set_tests_properties(m2_proxy PROPERTIES TIMEOUT 60)

qt_add_executable(m3_modification_tests M3ModificationTests.cpp)
target_link_libraries(m3_modification_tests PRIVATE interceptor_proxy Qt6::Test)
add_test(NAME m3_modification COMMAND m3_modification_tests)
set_tests_properties(m3_modification PROPERTIES TIMEOUT 60)

find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
    add_test(NAME m0_fixture_integrity
        COMMAND "${Python3_EXECUTABLE}" -B -m unittest discover
            -s "${CMAKE_CURRENT_SOURCE_DIR}" -p test_m0_fixtures.py -v
    )
    set_tests_properties(m0_fixture_integrity PROPERTIES TIMEOUT 30)
endif()
