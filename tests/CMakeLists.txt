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

qt_add_executable(m4_network_tests M4NetworkTests.cpp)
target_link_libraries(m4_network_tests PRIVATE interceptor_network Qt6::Test)
add_test(NAME m4_network COMMAND m4_network_tests)
set_tests_properties(m4_network PROPERTIES TIMEOUT 30)

find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
    add_test(NAME m0_fixture_integrity
        COMMAND "${Python3_EXECUTABLE}" -B -m unittest discover
            -s "${CMAKE_CURRENT_SOURCE_DIR}" -p test_m0_fixtures.py -v
    )
    set_tests_properties(m0_fixture_integrity PROPERTIES TIMEOUT 30)
endif()

qt_add_executable(m5_inspection_tests M5InspectionTests.cpp)
target_link_libraries(m5_inspection_tests PRIVATE interceptor_gui interceptor_inspection interceptor_proxy Qt6::Test)
add_test(NAME m5_inspection COMMAND m5_inspection_tests)
set_tests_properties(m5_inspection PROPERTIES
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
    TIMEOUT 120
)

qt_add_executable(m6_lab_preflight_tests M6LabPreflightTests.cpp)
target_link_libraries(m6_lab_preflight_tests PRIVATE interceptor_network Qt6::Test)
add_test(NAME m6_lab_preflight COMMAND m6_lab_preflight_tests)
set_tests_properties(m6_lab_preflight PROPERTIES TIMEOUT 30)

qt_add_executable(m6_pf_diagnostics_tests M6PfDiagnosticsTests.cpp)
target_link_libraries(m6_pf_diagnostics_tests PRIVATE interceptor_network Qt6::Test)
add_test(NAME m6_pf_diagnostics COMMAND m6_pf_diagnostics_tests)
set_tests_properties(m6_pf_diagnostics PROPERTIES TIMEOUT 30)

qt_add_executable(m6_route_neighbor_diagnostics_tests M6RouteNeighborDiagnosticsTests.cpp)
target_link_libraries(m6_route_neighbor_diagnostics_tests PRIVATE interceptor_network Qt6::Test)
add_test(NAME m6_route_neighbor_diagnostics COMMAND m6_route_neighbor_diagnostics_tests)
set_tests_properties(m6_route_neighbor_diagnostics PROPERTIES TIMEOUT 30)

qt_add_executable(m6_pf_anchor_operations_tests M6PfAnchorOperationsTests.cpp)
target_link_libraries(m6_pf_anchor_operations_tests PRIVATE interceptor_network Qt6::Test)
add_test(NAME m6_pf_anchor_operations COMMAND m6_pf_anchor_operations_tests)
set_tests_properties(m6_pf_anchor_operations PROPERTIES TIMEOUT 30)

qt_add_executable(m6_pf_anchor_qprocess_runner_tests M6PfAnchorQProcessRunnerTests.cpp)
target_link_libraries(m6_pf_anchor_qprocess_runner_tests PRIVATE interceptor_network Qt6::Test)
add_test(NAME m6_pf_anchor_qprocess_runner COMMAND m6_pf_anchor_qprocess_runner_tests)
set_tests_properties(m6_pf_anchor_qprocess_runner PROPERTIES TIMEOUT 30)

qt_add_executable(m6_unix_peer_credentials_tests M6UnixPeerCredentialsTests.cpp)
target_link_libraries(m6_unix_peer_credentials_tests PRIVATE interceptor_network Qt6::Test)
add_test(NAME m6_unix_peer_credentials COMMAND m6_unix_peer_credentials_tests)
set_tests_properties(m6_unix_peer_credentials PROPERTIES TIMEOUT 30)

qt_add_executable(m6_unix_socket_command_transport_tests M6UnixSocketCommandTransportTests.cpp)
target_link_libraries(m6_unix_socket_command_transport_tests PRIVATE interceptor_network Qt6::Test)
add_test(NAME m6_unix_socket_command_transport COMMAND m6_unix_socket_command_transport_tests)
set_tests_properties(m6_unix_socket_command_transport PROPERTIES TIMEOUT 30)
