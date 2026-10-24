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

    # Teardown can meet a pending destroy, and a watcher close callback can free itself.
    set(destroy_anchor "  if (stream->status & UDX_STREAM_CLOSED) {\n    debug_printf(\"udx: closing already closed stream")
    set(teardown_anchor "udx_teardown (udx_t *udx) {\n  udx->teardown = true;")
    set(close_anchor "  if (udx->teardown && socket != NULL && socket->streams == NULL) {")
    foreach(anchor IN ITEMS "${destroy_anchor}" "${teardown_anchor}" "${close_anchor}" "  ref_dec(event->udx);")
        string(FIND "${code}" "${anchor}" found)
        if(found EQUAL -1)
            message(FATAL_ERROR "libudx close path changed; review teardown before building")
        endif()
    endforeach()
    string(REPLACE "${destroy_anchor}"
        "  if (stream->status & (UDX_STREAM_CLOSED | UDX_STREAM_DESTROYING)) {\n    debug_printf(\"udx: closing already closed stream" code "${code}")
    string(REPLACE "${teardown_anchor}"
        "udx_teardown (udx_t *udx) {\n  if (udx->teardown) return;\n  udx->teardown = true;" code "${code}")
    # on_close can close the last stream's socket before close_stream resumes.
    string(REPLACE "${close_anchor}"
        "  if (udx->teardown && socket != NULL && !(socket->status & UDX_SOCKET_CLOSED) && socket->streams == NULL) {" code "${code}")
    string(REPLACE "  ref_dec(event->udx);" "  ref_dec(udx);" code "${code}")
    file(WRITE "${output}" "${code}")
endfunction()
