/* SPDX-License-Identifier: GPL-2.0 OR MIT
 *
 * Minimal Wintun API surface needed by nospoon-cpp.
 * Types match the official wintun.h shipped at https://www.wintun.net/
 * (Wintun 0.14.x, public domain dual-licensed MIT/GPL-2.0).
 *
 * We resolve every symbol via GetProcAddress at runtime so consumers
 * never need to link wintun.lib — only wintun.dll alongside the .exe.
 */

#pragma once

#ifdef _WIN32

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void *WINTUN_ADAPTER_HANDLE;
typedef void *WINTUN_SESSION_HANDLE;

typedef WINTUN_ADAPTER_HANDLE (WINAPI *WINTUN_CREATE_ADAPTER_FN)(
    LPCWSTR Name, LPCWSTR TunnelType, const GUID *RequestedGUID);
typedef WINTUN_ADAPTER_HANDLE (WINAPI *WINTUN_OPEN_ADAPTER_FN)(LPCWSTR Name);
typedef void (WINAPI *WINTUN_CLOSE_ADAPTER_FN)(WINTUN_ADAPTER_HANDLE Adapter);
typedef WINTUN_SESSION_HANDLE (WINAPI *WINTUN_START_SESSION_FN)(
    WINTUN_ADAPTER_HANDLE Adapter, DWORD Capacity);
typedef void (WINAPI *WINTUN_END_SESSION_FN)(WINTUN_SESSION_HANDLE Session);
typedef HANDLE (WINAPI *WINTUN_GET_READ_WAIT_EVENT_FN)(WINTUN_SESSION_HANDLE Session);
typedef BYTE *(WINAPI *WINTUN_RECEIVE_PACKET_FN)(
    WINTUN_SESSION_HANDLE Session, DWORD *PacketSize);
typedef void (WINAPI *WINTUN_RELEASE_RECEIVE_PACKET_FN)(
    WINTUN_SESSION_HANDLE Session, const BYTE *Packet);
typedef BYTE *(WINAPI *WINTUN_ALLOCATE_SEND_PACKET_FN)(
    WINTUN_SESSION_HANDLE Session, DWORD PacketSize);
typedef void (WINAPI *WINTUN_SEND_PACKET_FN)(
    WINTUN_SESSION_HANDLE Session, const BYTE *Packet);
typedef DWORD (WINAPI *WINTUN_GET_RUNNING_DRIVER_VERSION_FN)(VOID);

/* Errors returned via GetLastError() that nospoon cares about. */
#define WINTUN_ERROR_NO_MORE_ITEMS  259  /* normal: ring drained */
#define WINTUN_ERROR_HANDLE_EOF     38   /* fatal: session ended */

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif  /* _WIN32 */
