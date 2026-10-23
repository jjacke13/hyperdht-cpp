# Keep the submodule pristine; compile a guarded copy on every build path.
function(hyperdht_harden_udx source output)
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
        "${source}" "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/udx-reset-guard.h")
    file(READ "${source}" code)
    set(anchor "  // We expect this to be a stream packet from now on")
    string(FIND "${code}" "${anchor}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "libudx packet path changed; review the reset guard before building")
    endif()
    file(READ "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/udx-reset-guard.h" guard)
    string(REPLACE "${anchor}" "  if ((type & UDX_HEADER_DESTROY) && !hyperdht_udx_reset_source(stream, socket, addr)) return 1;\n${anchor}" code "${code}")
    # Place the helper before process_packet, after libudx's address helpers.
    string(REPLACE "static int\nprocess_packet (" "${guard}\nstatic int\nprocess_packet (" code "${code}")
    file(WRITE "${output}" "${code}")
endfunction()
