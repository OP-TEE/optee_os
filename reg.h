
#ifndef _REGISTRY_H
#define _REGISTRY_H

#ifdef __cplusplus
	extern "C" {
#endif

#include "Windows.h"
#include "tchar.h"
#include "options.h"

BOOL WriteRegistryKey( HKEY hKey, TCHAR *szKeyPath, TCHAR *szKeyName, TCHAR *szNewValue );
BOOL ReadRegistryKey ( HKEY hKey, TCHAR *szKeyPath, TCHAR *szKeyName, TCHAR *szBuffer, int iSize );
BOOL WriteRegistryDWORD( HKEY hKey, TCHAR *szKeyPath, TCHAR *szKeyName, DWORD NewValue );
DWORD ReadRegistryDWORD( HKEY hKey, TCHAR *szKeyPath, TCHAR *szKeyName );
BOOL WriteRegistryBinary( HKEY hKey, TCHAR *szKeyPath, TCHAR *szKeyName, void *pvNewValue, int iBufLen );
BOOL ReadRegistryBinary( HKEY hKey, TCHAR *szKeyPath, TCHAR *szKeyName, void *pvBuffer, DWORD dwSize );
BOOL EnumKeys( TCHAR *szBuffer, TCHAR *szName, int namelen, int bufferlen );
BOOL DeleteRegistryKey( HKEY hKey, TCHAR *szKeyPath, TCHAR *szKeyName );

#ifdef __cplusplus
	}
#endif

#endif /* _REGISTRY_H */