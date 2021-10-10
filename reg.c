
#include "reg.h"

BOOL WriteRegistryKey( HKEY hKey, TCHAR *szKeyPath, TCHAR *szKeyName, TCHAR *szNewValue )
{
	DWORD result;
	HKEY phKey;
	
	if( RegCreateKeyEx( hKey, szKeyPath, 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, 0, &phKey, &result ) != ERROR_SUCCESS )
		return FALSE;

	if( RegSetValueEx( phKey, szKeyName, 0, REG_SZ, (BYTE*)szNewValue, (lstrlen(szNewValue)+1)*sizeof(TCHAR) ) != ERROR_SUCCESS )
		return FALSE;

	RegCloseKey( phKey );
	return TRUE;
}

BOOL ReadRegistryKey ( HKEY hKey, TCHAR *szKeyPath, TCHAR *szKeyName, TCHAR *szBuffer, int iSize )
{
	HKEY phKey;
	DWORD dwCount = iSize;
	ULONG theLong;
	LONG lResult = 0;

	if( !RegOpenKeyEx( hKey, szKeyPath, 0, KEY_QUERY_VALUE, &phKey ) == ERROR_SUCCESS )
		return FALSE;

	theLong = REG_SZ;

	lResult = RegQueryValueEx( phKey, szKeyName, 0, &theLong, (BYTE*)szBuffer, &dwCount );

	if ( lResult == ERROR_SUCCESS )
	{
		RegCloseKey( phKey );
		return TRUE;
	}
	
	RegCloseKey( phKey );
	return FALSE;
}

BOOL WriteRegistryDWORD( HKEY hKey, TCHAR *szKeyPath, TCHAR *szKeyName, DWORD NewValue )
{
	DWORD result;
	HKEY phKey;
	
	if( RegCreateKeyEx( hKey, szKeyPath, 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, 0, &phKey, &result ) != ERROR_SUCCESS )
		return FALSE;

	if( RegSetValueEx( phKey, szKeyName, 0, REG_DWORD, (BYTE*)&NewValue, sizeof(DWORD) ) != ERROR_SUCCESS )
		return FALSE;

	RegCloseKey( phKey );
	return TRUE;
}

DWORD ReadRegistryDWORD( HKEY hKey, TCHAR *szKeyPath, TCHAR *szKeyName )
{
	HKEY phKey;
	DWORD dwReturn = 0;
	DWORD result;
	DWORD dwType = REG_DWORD;
	DWORD dwSize = 4;

	if( RegCreateKeyEx( hKey, szKeyPath, 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, 0, &phKey, &result ) != ERROR_SUCCESS)
		return 0;

	if( RegQueryValueEx( phKey, szKeyName, 0, &dwType, (LPBYTE)&dwReturn, &dwSize ) != ERROR_SUCCESS )
		return 0;

	RegCloseKey( phKey );

	return dwReturn;
}

BOOL WriteRegistryBinary( HKEY hKey, TCHAR *szKeyPath, TCHAR *szKeyName, void *pvNewValue, int iBufLen )
{
	DWORD result;
	HKEY phKey;

	if( RegCreateKeyEx( hKey, szKeyPath, 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, 0, &phKey, &result ) != ERROR_SUCCESS )
		return FALSE;

	if( RegSetValueEx( phKey, szKeyName, 0, REG_BINARY, pvNewValue, iBufLen ) != ERROR_SUCCESS )
		return FALSE;

	RegCloseKey( phKey );
	return TRUE;
}

BOOL ReadRegistryBinary( HKEY hKey, TCHAR *szKeyPath, TCHAR *szKeyName, void *pvBuffer, DWORD dwSize )
{
	DWORD result;
	HKEY phKey;
	DWORD dwType = REG_BINARY;

	if( RegCreateKeyEx( hKey, szKeyPath, 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &phKey, &result ) != ERROR_SUCCESS )
		return FALSE;

	if( RegQueryValueEx( phKey, szKeyName, 0, &dwType, pvBuffer, &dwSize ) != ERROR_SUCCESS )
		return FALSE;
	
	RegCloseKey( phKey );
	return TRUE;
}

BOOL DeleteRegistryKey( HKEY hKey, TCHAR *szKeyPath, TCHAR *szKeyName )
{
	DWORD result;
	HKEY phKey;
	
	if( RegCreateKeyEx( hKey, szKeyPath, 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &phKey, &result ) != ERROR_SUCCESS )
		return FALSE;
	if( RegDeleteValue( phKey, szKeyName ) != ERROR_SUCCESS )
		return FALSE;

	RegCloseKey( phKey );
	return TRUE;
}

BOOL EnumKeys( TCHAR *szBuffer, TCHAR *szName, int namelen, int bufferlen )
{
	HKEY phKey;
	LONG lResult       = 0;
	DWORD dwBufferSize = namelen;
	DWORD result       = 0;
	static int index   = 0;

	if( RegCreateKeyEx( ROOT_KEY, ROOT_RECENT_KEY, 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, 0, &phKey, &result ) != ERROR_SUCCESS )
		return FALSE;
	
	lResult = RegEnumValue( phKey, (DWORD)index, szName, &dwBufferSize, 0, 0, (BYTE*)szBuffer, &bufferlen );

	if( lResult != ERROR_NO_MORE_ITEMS && lResult != ERROR_SUCCESS )
	{
		RegCloseKey( phKey );
		return FALSE;
	}

	if( lResult == ERROR_NO_MORE_ITEMS )
	{
		index = 0;
		RegCloseKey( phKey );
		return FALSE;
	}

	RegCloseKey( phKey );
	index ++;
	return TRUE;
}