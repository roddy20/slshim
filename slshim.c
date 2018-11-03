#define _WIN32_WINNT _WIN32_WINNT_WIN7
#define CryptGetHashParam CryptGetHashParam_dummy
#include <windows.h>
#include <stdint.h>
#include <winternl.h>
#include <stdio.h>
#include <ntstatus.h>
#include <shlwapi.h>
#undef CryptGetHashParam
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
#define malloc(n) LocalAlloc(LMEM_ZEROINIT, n)
#define SL_E_VALUE_NOT_FOUND 0xC004F012
#define SL_E_NOT_SUPPORTED 0xC004F016
typedef DWORD SLDATATYPE;
typedef GUID SLID;
typedef DWORD SLIDTYPE;
#define DEADBEEF 0xdeadbeef
#define APP "SYSTEM\\Tokens"
#define KERNEL "SYSTEM\\Tokens\\Kernel"
typedef struct {SLID SkuId; DWORD eStatus; DWORD dwGraceTime; DWORD dwTotalGraceDays; HRESULT hrReason; UINT64 qwValidityExpiration;} SL_LICENSING_STATUS;
#define	F_INVALID		0x01
#define F_PREFIX		0x02
#define	F_REX			0x04
#define F_MODRM			0x08
#define F_SIB			0x10
#define F_DISP			0x20
#define F_IMM			0x40
#define F_RELATIVE		0x80
#define OP_NONE			0x00
#define OP_INVALID		0x80
#define OP_DATA_I8		0x01
#define OP_DATA_I16		0x02
#define OP_DATA_I16_I32		0x04
#define OP_DATA_I16_I32_I64	0x08
#define OP_EXTENDED		0x10
#define OP_RELATIVE		0x20
#define OP_MODRM		0x40
#define OP_PREFIX		0x80
typedef void *HSLC, *HSLP;
static SLID consumed_skuids[256];
static int nconsumed;
static DWORD tbuf[16384];

static HRESULT sl_get(const char *path, const WCHAR *name, SLDATATYPE *t, UINT *pcbValue, PBYTE *ppbValue)
{
	DWORD pop = 0;
	DWORD ot = 4;
	DWORD sz = sizeof(tbuf);
	HKEY k;

	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &k))
		return SL_E_VALUE_NOT_FOUND;

	RegQueryValueExW(k, L"Populate", 0, NULL, (BYTE*)&pop, &ot);

	if (pop) {
		HKEY k2;
		if (!RegOpenKeyExA(HKEY_LOCAL_MACHINE, path, 0, KEY_READ|KEY_WRITE, &k2)) {
			RegCloseKey(k);
			k = k2;
		} else pop = 0;
	}

	int ret = RegQueryValueEx(k, name, 0, (DWORD*)&ot, (void*)&tbuf, (DWORD*)&sz);
	if (ret) {
		if (*name == L'*') {
			ret = S_OK;
			sz = 4;
			ot = REG_MULTI_SZ;
			tbuf[0] = 0;
		} else {
			sz = sizeof(tbuf);
			ret = SL_E_VALUE_NOT_FOUND;
			WCHAR valn[256];
			DWORD valnsz = 256;
			int best = -1;
			int bestlen = -1;
			for (int i = 0; (valnsz = sizeof(valn)/2) && !RegEnumValue(k, i, valn, &valnsz, 0, NULL, NULL, NULL); i++) {
				if (PathMatchSpec(name, valn)) {
					if (((int)valnsz) > bestlen) {
						bestlen = valnsz;
						best = i;
					}
				}
			}
			if (best == -1)
				goto out;
			valnsz = sizeof(valn)/2;
			if (RegEnumValue(k, best, valn, &valnsz, 0, &ot, (void*)tbuf, &sz))
				goto out;

			if (pop) 
				RegSetValueEx(k, name, 0, ot, (void*)tbuf, sz);
			ret = S_OK;
		}
	}
	if ((ot == REG_DWORD) && (tbuf[0] == DEADBEEF)) {
		ret = SL_E_VALUE_NOT_FOUND;
		goto out;
	}
	if ((!ret) && ((t == ((void*)-1)) && (pcbValue == ((void*)-1)))) {
		*((DWORD*)ppbValue) = tbuf[0];
		ret = S_OK;
		goto out;
	}

	if (ppbValue) {
		*ppbValue = LocalAlloc(0, sz);
		memcpy(*ppbValue, (void*)tbuf, sz);
	}
	if (pcbValue) *pcbValue = sz;
	if (t) *t = ot;

	out:;
	RegCloseKey(k);
	return ret;
}

HRESULT WINAPI SLOpen(HSLC *out) {*out = (void*)1; return S_OK;}

HRESULT WINAPI SLGetApplicationInformation(HSLC hSLC, SLID *pApplicationId, PWSTR pwszValueName, SLDATATYPE *peDataType, UINT *pcbValue, PBYTE *ppbValue)
{
	return sl_get(APP, pwszValueName, peDataType, pcbValue, ppbValue);
}

HRESULT WINAPI SLGetGenuineInformation(const SLID *pAppId, PCWSTR pwszValueName, SLDATATYPE *peDataType, UINT *pcbValue, BYTE **ppbValue)
{
	return sl_get(APP, pwszValueName, peDataType, pcbValue, ppbValue);
}

HRESULT WINAPI SLGetSLIDList(HSLC hSLC, SLIDTYPE eQueryIdType, SLID *pQueryId, SLIDTYPE eReturnIdType, UINT *pnReturnIds, SLID **ppReturnIds)
{
	*ppReturnIds = malloc(sizeof(SLID) * nconsumed);
	memcpy((void*)*ppReturnIds, (void*)consumed_skuids, nconsumed * sizeof(SLID));
	*pnReturnIds = nconsumed;
	return S_OK;
}

HRESULT WINAPI SLInstallLicense(HSLC hSLC, UINT cbLicenseBlob, const BYTE *pbLicenseBlob, SLID *pLicenseFileId)
{
	*pLicenseFileId = (SLID){0};
	return S_OK;
}

HRESULT WINAPI SLGetPKeyInformation(HSLC hSLC, SLID *pPKeyId, PWSTR pwszValueName, SLDATATYPE *peDataType, UINT *pcbValue, PBYTE *ppbValue)
{
	return sl_get(APP, pwszValueName, peDataType, pcbValue, ppbValue);
}

HRESULT WINAPI SLGetLicensingStatusInformation(HSLC hSLC, SLID *pAppID, SLID *pProductSkuId, PWSTR pwszRightName, UINT *pnStatusCount, SL_LICENSING_STATUS **ppLicensingStatus)
{
	SL_LICENSING_STATUS *entry = malloc(sizeof(SL_LICENSING_STATUS) * nconsumed);
	for (int i = 0; i < nconsumed; i++) {
		memcpy((void*)&entry[i].SkuId, (void*)&consumed_skuids[i], sizeof(SLID));
		entry[i].eStatus = 1;
	}
	*pnStatusCount = nconsumed;
	*ppLicensingStatus = entry;
	return S_OK;
}

HRESULT WINAPI SLGetPolicyInformation(HSLC hSLC, PWSTR pwszValueName, SLDATATYPE* peDataType, UINT* pcbValue, PBYTE* ppbValue)
{
	return sl_get(APP, pwszValueName, peDataType, pcbValue, ppbValue);
}

HRESULT WINAPI SLGetPolicyInformationDWORD(HSLC hSLC, PWSTR pwszValueName, DWORD* pdwValue)
{
	return SLGetPolicyInformation(hSLC, pwszValueName, (void*)-1, (void*)-1, (PBYTE*)pdwValue);
}

HRESULT WINAPI SLConsumeRight(HSLC hSLC, SLID *pAppId, SLID *pProductSkuId, PWSTR pwszRightName, PVOID pvReserved)
{
	if (!pProductSkuId) {
		WCHAR buf[64];
		if (!pAppId)
			return SL_E_NOT_SUPPORTED;
		StringFromGUID2(pAppId, buf, 64);
		WCHAR *bufp = NULL;
		sl_get(APP, buf, NULL, NULL, (BYTE**)&bufp);
		if (bufp) {
			int i;
			for(i = 0; *bufp; bufp = bufp + wcslen(bufp)+1, i++) {
				CLSIDFromString(bufp, &consumed_skuids[i]);
			}
			nconsumed = i;
			LocalFree(bufp);
		}
	} else {
		memcpy((void*)&consumed_skuids, (void*)pProductSkuId, sizeof(SLID));
		nconsumed = 1;
	}
	return S_OK;
}

HRESULT WINAPI SLGetWindowsInformation(PCWSTR pwszValueName, SLDATATYPE *peDataType, UINT *pcbValue, PBYTE *ppbValue)
{
	__declspec(dllimport) NTSTATUS NTAPI NtQueryLicenseValue(PUNICODE_STRING,DWORD*,PVOID,DWORD,DWORD*);
	if (sl_get(KERNEL, pwszValueName, peDataType, pcbValue, ppbValue) == SL_E_VALUE_NOT_FOUND) {
		UNICODE_STRING us;
		us.Buffer = (void*)pwszValueName;
		us.MaximumLength = (us.Length = wcslen(pwszValueName)*2)+2;
		ULONG sz = sizeof(tbuf);
		ULONG typ;
		if (!NT_SUCCESS(NtQueryLicenseValue(&us, &typ, tbuf, sizeof(tbuf), &sz)))
			return SL_E_VALUE_NOT_FOUND;
		if (pcbValue == (void*)-1) {
			*((DWORD*)ppbValue) = tbuf[0];
			return S_OK;
		}
		if (peDataType)
			*peDataType = typ;
		if (pcbValue)
			*pcbValue = sz;
		if (ppbValue) {
			*ppbValue = LocalAlloc(0, sz);
			memcpy(*ppbValue, (void*)tbuf, sz);
		}
	}
	return S_OK;
}

HRESULT WINAPI SLGetWindowsInformationDWORD(PCWSTR pwszValueName, DWORD* pdwValue)
{
	return SLGetWindowsInformation(pwszValueName, (void*)-1, (void*)-1, (PBYTE*)pdwValue);
}

BOOL APIENTRY WINAPI dll_main(HINSTANCE hModule, DWORD code, LPVOID ress)
{
	static int doneinit;
	if (code != DLL_PROCESS_ATTACH)
		return TRUE;
	if (doneinit)
		return TRUE;
	doneinit = 1;
	nconsumed = 1;
	return TRUE;
}

HRESULT WINAPI fill1(DWORD *g) {*g = 0; return S_OK;}
HRESULT WINAPI fill2(DWORD *g, void *b) {*g = 0; return S_OK;}
HRESULT WINAPI fill3(void *a, void *b, DWORD *g) {*g = 0; return S_OK;}
HRESULT WINAPI ok0() {return S_OK;}
HRESULT WINAPI ok1(void *a1) {return S_OK;}
HRESULT WINAPI ok2(void *a1, void *a2) {return S_OK;}
HRESULT WINAPI ok3(void *a1, void *a2, void *a3) {return S_OK;}
HRESULT WINAPI ok4(void *a1, void *a2, void *a3, void *a4) {return S_OK;}
HRESULT WINAPI ok5(void *a1, void *a2, void *a3, void *a4, void *a5) {return S_OK;}
HRESULT WINAPI unsupp3(void *a1,void*a2,void*a3) {return SL_E_NOT_SUPPORTED;}
HRESULT WINAPI unsupp4(void *a1,void*a2,void*a3,void*a4) {return SL_E_NOT_SUPPORTED;}
HRESULT WINAPI unsupp6(void *a1,void*a2,void*a3,void*a4,void*a5,void*a6) {return SL_E_NOT_SUPPORTED;}