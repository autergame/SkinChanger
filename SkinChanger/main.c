#define CURL_STATICLIB
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <Windows.h>
#include <direct.h>
#include <locale.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include "cJSON.h"
#include "libs/zlib.h"
#include "libs/zstd.h"
#include "libs/curl.h"
#pragma comment(lib, "ws2_32")
#pragma comment(lib, "crypt32")
#pragma comment(lib, "wldap32")
#pragma comment(lib, "advapi32")
#pragma comment(lib, "normaliz")
#pragma comment(lib, "libs/libcurl")
#pragma comment(lib, "libs/zlibstatic")
#pragma comment(lib, "libs/zstdstatic")

static int mod_table[] = {
    0, 2, 1
};
static char encoding_table[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/'
};
char* base64_encode(char* data, int input_length)
{
    int output_length = 4 * ((input_length + 2) / 3);
    char* encoded_data = (char*)calloc(output_length, 1);
    for (int i = 0, j = 0; i < input_length;)
    {
        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }
    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[output_length - 1 - i] = '=';
    encoded_data[output_length] = '\0';
    return encoded_data;
}
typedef struct url_data
{
    size_t size;
    char* text;
} url_data;
size_t write_data(void* ptr, size_t size, size_t nmemb, url_data* data)
{
    size_t index = data->size;
    size_t n = (size * nmemb);
    data->size += (size * nmemb);
    char* tmp = realloc(data->text, data->size + 1);
    if (tmp)
        data->text = tmp;
    else {
        if (data->text)
            free(data->text);
        fprintf(stderr, "Failed to allocate memory\n");
        return 0;
    }
    memcpy((data->text + index), ptr, n);
    data->text[data->size] = '\0';
    return size * nmemb;
}
char* download_url(char* url, char* port, char* auth, char* protocol)
{
    url_data data;
    data.size = 0;
    data.text = calloc(1, 1);
    curl_global_init(CURL_GLOBAL_ALL);
    CURL* curl = curl_easy_init();
    if (curl)
    {
        char* authfull = calloc(256, 1);
        char* hostfull = calloc(256, 1);
        struct curl_slist* headers = NULL;
        sprintf(authfull, "Authorization: Basic %s", auth);
        sprintf(hostfull, "https://127.0.0.1:%s%s", port, url);
        curl_easy_setopt(curl, CURLOPT_URL, hostfull);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, protocol);
        headers = curl_slist_append(headers, "Connection: close");
        headers = curl_slist_append(headers, authfull);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK)
            fprintf(stderr, "Failed to curl_easy_perform: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        free(authfull);
        free(hostfull);
    }
    curl_global_cleanup();
    int nLength = MultiByteToWideChar(CP_UTF8, 0, data.text, strlen(data.text) + 1, NULL, NULL);
    wchar_t* bstrWide = SysAllocStringLen(NULL, nLength);
    MultiByteToWideChar(CP_UTF8, 0, data.text, strlen(data.text) + 1, bstrWide, nLength);
    nLength = WideCharToMultiByte(CP_ACP, 0, bstrWide, -1, NULL, 0, NULL, NULL);
    char* pszAnsi = (char*)malloc(nLength);
    WideCharToMultiByte(CP_ACP, 0, bstrWide, -1, pszAnsi, nLength, NULL, NULL);
    SysFreeString(bstrWide);
    free(data.text);
    return pszAnsi;
}

typedef struct Process
{
    HANDLE handle;
    DWORD processid;
    DWORD baselength;
    DWORD baseaddress;
    char filepath[MAX_PATH];
} Process;
static const DWORD PROCESS_NEEDED_ACCESS = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | SYNCHRONIZE;
Process* ProcessFind(char* name)
{
    Process* process = (Process*)calloc(1, sizeof(Process));
    PROCESSENTRY32 entry = { .dwSize = sizeof(PROCESSENTRY32) };
    while (1)
    {
        HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (Process32First(handle, &entry))
        {
            do
            {
                if (strcmp(entry.szExeFile, name) == 0)
                {
                    process->handle = OpenProcess(PROCESS_NEEDED_ACCESS, 0, entry.th32ProcessID);
                    HANDLE hmodule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, entry.th32ProcessID);
                    MODULEENTRY32 mEntry = { .dwSize = sizeof(MODULEENTRY32) };
                    do {
                        if (strcmp(mEntry.szModule, name) == 0)
                        {
                            process->processid = entry.th32ProcessID;
                            process->baselength = mEntry.modBaseSize;
                            process->baseaddress = (DWORD)mEntry.hModule;
                            K32GetModuleFileNameExA(process->handle, NULL, process->filepath, MAX_PATH);
                            return process;
                        }
                    } while (Module32Next(hmodule, &mEntry));
                }
            } while (Process32Next(handle, &entry));
        }
        Sleep(50);
    }
    return NULL;
}
uint8_t DataCompare(uint8_t* data, uint8_t* signature, uint8_t* mask, DWORD length)
{
    for (DWORD i = 0; i < length; i++)
        if ((data[i] != signature[i]) && (mask[i] == 'x'))
            return 0;
    return 1;
}
DWORD FindAddress(uint8_t* signature, uint8_t* mask, int length, uint8_t* baseaddress, DWORD baselength)
{
    for (DWORD i = 0; i < (baselength - length); i++)
        if (DataCompare(baseaddress + i, signature, mask, length))
            return i;
    return 0;
}
void* AllocateMemory(HANDLE handle, DWORD size)
{
    void* ptr = VirtualAllocEx(handle, 0, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!ptr)
        printf("\nFailed to allocate memory\n");
    return ptr;
}
uint8_t* ReadMemory(HANDLE handle, void* address, DWORD size)
{
    uint8_t* buffer = (uint8_t*)malloc(size);
    if (!ReadProcessMemory(handle, address, buffer, size, NULL))
    {
        printf("\nFailed to read memory: %p\n", address);
        return 0;
    }
    return buffer;
}
uint8_t WriteMemory(HANDLE handle, void* address, uint8_t* buffer, DWORD length)
{
    if (!WriteProcessMemory(handle, address, buffer, length, NULL))
    {
        printf("\nFailed to write memory: %p\n", address);
        return 0;
    }
    return 1;
}
uint8_t MarkMemoryExecutable(HANDLE handle, void* address, DWORD size)
{
    DWORD old = 0;
    if (!VirtualProtectEx(handle, address, size, PAGE_EXECUTE, &old))
    {
        printf("\nFailed to mark region as executable: %p\n", address);
        return 0;
    }
    return 1;
}
DWORD WaitPointerNonZero(HANDLE handle, void* address)
{
    uint32_t buffer;
    do
    {
        Sleep(1);
        if (!ReadProcessMemory(handle, address, &buffer, 4, NULL))
        {
            printf("\nFailed to wait pointer non zero: %p\n", address);
            return 0;
        }
    } while (buffer == 0);
    return buffer;
}
typedef struct EVP_PKEY_METHOD
{
    int32_t pkey_id;
    int32_t flags;
    int32_t init;
    int32_t copy;
    int32_t cleanup;
    int32_t paramgen_init;
    int32_t paramgen;
    int32_t keygen_init;
    int32_t keygen;
    int32_t sign_init;
    int32_t sign;
    int32_t verify_init;
    uint32_t verify;
    int32_t verify_recover_init;
    int32_t verify_recover;
    int32_t signctx_init;
    int32_t signctx;
    int32_t verifyctx_init;
    int32_t verifyctx;
    int32_t encrypt_init;
    int32_t encrypt;
    int32_t decrypt_init;
    int32_t decrypt;
    int32_t derive_init;
    int32_t derive;
    int32_t ctrl;
    int32_t ctrl_str;
    int32_t digestsign;
    int32_t digestverify;
    int32_t check;
    int32_t public_check;
    int32_t param_check;
    int32_t digest_custom;
} EVP_PKEY_METHOD;
typedef struct FileProvider
{
    uint32_t vtable;
    uint32_t list;
    uint32_t prefixFn;
    uint8_t prefix[256];
} FileProvider;
typedef struct FileProviderVtable
{
    uint32_t Open;
    uint32_t CheckAccess;
    uint32_t CreateIterator;
    uint32_t VectorDeleter;
    uint32_t IsRads;
} FileProviderVtable;
typedef struct FileProviderList
{
    uint32_t fileProviderPointer0;
    uint32_t fileProviderPointer1;
    uint32_t fileProviderPointer2;
    uint32_t fileProviderPointer3;
    uint32_t size;
} FileProviderList;
static uint8_t* fpmask = "xxxxxx????xxxxxx";
static uint8_t* pmethmask = "x????xxxxxxx?x????xx????xxxxx";
static uint8_t* fpsignature = "\x56\x8B\x74\x24\x08\xB8\x99\x99\x99\x99\x33\xC9\x0F\x1F\x40\x00";
static uint8_t* pmethsignature = "\x68\x99\x99\x99\x99\x6A\x04\x6A\x12\x8D\x44\x24\x99\x68\x99\x99\x99\x99\x50\xE8\x99\x99\x99\x99\x83\xC4\x14\x85\xC0";
static uint8_t codeVerify[0x10] = {
    0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
};
static uint8_t PrefixFn[0x30] = {
    0x57, 0x56, 0x8b, 0x54, 0x24, 0x0c, 0x8b, 0x74, 0x24, 0x14, 0x89, 0xd7,
    0xac, 0xaa, 0x84, 0xc0, 0x75, 0xfa, 0x8b, 0x74, 0x24, 0x10, 0x83, 0xef,
    0x01, 0xac, 0xaa, 0x84, 0xc0, 0x75, 0xfa, 0x5e, 0x89, 0xd0, 0x5f, 0xc3,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
};
static uint8_t Open[0x50] = {
    0x56, 0x53, 0x81, 0xec, 0x14, 0x02, 0x00, 0x00, 0x8b, 0x41, 0x04, 0x8b, 0x58, 0x08,
    0x8b, 0x03, 0x8b, 0x30, 0x8d, 0x41, 0x0c, 0x89, 0x44, 0x24, 0x08, 0x8b, 0x84, 0x24,
    0x20, 0x02, 0x00, 0x00, 0x89, 0x44, 0x24, 0x04, 0x8d, 0x44, 0x24, 0x10, 0x89, 0x04,
    0x24, 0xff, 0x51, 0x08, 0x8b, 0x94, 0x24, 0x24, 0x02, 0x00, 0x00, 0x89, 0xd9, 0x89,
    0x04, 0x24, 0x89, 0x54, 0x24, 0x04, 0xff, 0xd6, 0x83, 0xec, 0x08, 0x81, 0xc4, 0x14,
    0x02, 0x00, 0x00, 0x5b, 0x5e, 0xc2, 0x08, 0x00, 0x90, 0x90,
};
static uint8_t CheckAccess[0x50] = {
    0x56, 0x53, 0x81, 0xec, 0x14, 0x02, 0x00, 0x00, 0x8b, 0x41, 0x04, 0x8b, 0x58, 0x08,
    0x8b, 0x03, 0x8b, 0x70, 0x04, 0x8d, 0x41, 0x0c, 0x89, 0x44, 0x24, 0x08, 0x8b, 0x84,
    0x24, 0x20, 0x02, 0x00, 0x00, 0x89, 0x44, 0x24, 0x04, 0x8d, 0x44, 0x24, 0x10, 0x89,
    0x04, 0x24, 0xff, 0x51, 0x08, 0x8b, 0x94, 0x24, 0x24, 0x02, 0x00, 0x00, 0x89, 0xd9,
    0x89, 0x04, 0x24, 0x89, 0x54, 0x24, 0x04, 0xff, 0xd6, 0x83, 0xec, 0x08, 0x81, 0xc4,
    0x14, 0x02, 0x00, 0x00, 0x5b, 0x5e, 0xc2, 0x08, 0x00, 0x90,
};
static uint8_t CreateIterator[0x10] = {
    0x31, 0xc0, 0xc2, 0x08, 0x00, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
};
static uint8_t VectorDeleter[0x10] = {
    0x89, 0xc8, 0xc2, 0x04, 0x00, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
};
static uint8_t IsRads[0x10] = {
    0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
};
DWORD WINAPI modskin(LPVOID Param)
{
    while (1)
    {
        Process* process = ProcessFind("League of Legends.exe");
        WaitForInputIdle(process->handle, INFINITE);
        uint8_t* buffer = (uint8_t*)malloc(process->baselength);
        for (DWORD p = 0; p != process->baselength; p += 0x1000)
            ReadProcessMemory(process->handle, (void*)(process->baseaddress + p), buffer + p, 0x1000, NULL);
        DWORD res_fp = FindAddress(fpsignature, fpmask, 16, buffer, process->baselength) + 6;
        DWORD res_pmeth = FindAddress(pmethsignature, pmethmask, 29, buffer, process->baselength) + 14;
        if (res_fp == 6 || res_pmeth == 14)
            printf("\nFailed to get offsets!\n");
        DWORD off_fp = *((DWORD*)(buffer + res_fp)) - process->baseaddress;
        DWORD off_pmeth = *((DWORD*)(buffer + res_pmeth)) - process->baseaddress;
        void* codePointer = AllocateMemory(process->handle, 0x900);
        assert(codePointer != 0);
        void* codeVerifyPointer = (DWORD)codePointer + 0x000;
        void* codePrefixFnPointer = (DWORD)codePointer + 0x100;
        void* codeOpenPointer = (DWORD)codePointer + 0x200;
        void* codeCheckAccessPointer = (DWORD)codePointer + 0x300;
        void* codeCreateIteratorPointer = (DWORD)codePointer + 0x400;
        void* codeVectorDeleterPointer = (DWORD)codePointer + 0x500;
        void* codeIsRadsPointer = (DWORD)codePointer + 0x600;
        assert(WriteMemory(process->handle, codeVerifyPointer, codeVerify, 0x10) != 0);
        assert(WriteMemory(process->handle, codePrefixFnPointer, PrefixFn, 0x30) != 0);
        assert(WriteMemory(process->handle, codeOpenPointer, Open, 0x50) != 0);
        assert(WriteMemory(process->handle, codeCheckAccessPointer, CheckAccess, 0x50) != 0);
        assert(WriteMemory(process->handle, codeCreateIteratorPointer, CreateIterator, 0x10) != 0);
        assert(WriteMemory(process->handle, codeVectorDeleterPointer, VectorDeleter, 0x10) != 0);
        assert(WriteMemory(process->handle, codeIsRadsPointer, IsRads, 0x10) != 0);
        assert(MarkMemoryExecutable(process->handle, codePointer, 0x900) != 0);
        DWORD modifiedPMethPointer = AllocateMemory(process->handle, sizeof(EVP_PKEY_METHOD));
        assert(modifiedPMethPointer != 0);
        void* orgignalPMethArrayPointer = off_pmeth + process->baseaddress;
        void* originalPMethFirstPointer = WaitPointerNonZero(process->handle, orgignalPMethArrayPointer);
        EVP_PKEY_METHOD* originalPMeth = (EVP_PKEY_METHOD*)ReadMemory(process->handle, originalPMethFirstPointer, sizeof(EVP_PKEY_METHOD));
        assert(originalPMeth != 0);
        originalPMeth->verify = codeVerifyPointer;
        assert(WriteMemory(process->handle, modifiedPMethPointer, originalPMeth, sizeof(EVP_PKEY_METHOD)) != 0);
        assert(WriteMemory(process->handle, orgignalPMethArrayPointer, &modifiedPMethPointer, 4) != 0);
        DWORD orginalFileProviderListPointer = off_fp + process->baseaddress;
        DWORD modifiedFileProviderPointer = AllocateMemory(process->handle, sizeof(FileProvider));
        assert(modifiedFileProviderPointer != 0);
        DWORD modifiedFileProviderVtablePointer = AllocateMemory(process->handle, sizeof(FileProviderVtable));
        assert(modifiedFileProviderVtablePointer != 0);
        FileProvider fpstruct = {
            .vtable = modifiedFileProviderVtablePointer,
            .list = orginalFileProviderListPointer,
            .prefixFn = codePrefixFnPointer
        };
        strcat_s(fpstruct.prefix, 256, (char*)Param);
        assert(WriteMemory(process->handle, modifiedFileProviderPointer, &fpstruct, sizeof(fpstruct)) != 0);
        FileProviderVtable fpvtablestruct = {
            .Open = codeOpenPointer,
            .CheckAccess = codeCheckAccessPointer,
            .CreateIterator = codeCreateIteratorPointer,
            .VectorDeleter = codeVectorDeleterPointer,
            .IsRads = codeIsRadsPointer
        };
        assert(WriteMemory(process->handle, modifiedFileProviderVtablePointer, &fpvtablestruct, sizeof(fpvtablestruct)) != 0);
        assert(WaitPointerNonZero(process->handle, orginalFileProviderListPointer) != 0);
        FileProviderList* originalFileProviderList = (FileProviderList*)ReadMemory(process->handle, orginalFileProviderListPointer, sizeof(FileProviderList));
        FileProviderList fpliststruct = {
            .fileProviderPointer0 = modifiedFileProviderPointer,
            .fileProviderPointer1 = originalFileProviderList->fileProviderPointer0,
            .fileProviderPointer2 = originalFileProviderList->fileProviderPointer1,
            .fileProviderPointer3 = originalFileProviderList->fileProviderPointer2,
            .size = originalFileProviderList->size + 1
        };
        assert(WriteMemory(process->handle, orginalFileProviderListPointer, &fpliststruct, sizeof(fpliststruct)) != 0);
        WaitForSingleObject(process->handle, INFINITE);
        free(buffer);
    }
}

uint64_t PRIME1 = 0x9E3779B185EBCA87ULL;
uint64_t PRIME2 = 0xC2B2AE3D27D4EB4FULL;
uint64_t PRIME3 = 0x165667B19E3779F9ULL;
uint64_t PRIME4 = 0x85EBCA77C2B2AE63ULL;
uint64_t PRIME5 = 0x27D4EB2F165667C5ULL;
uint64_t xxread8(const void* memPtr)
{
    uint8_t val;
    memcpy(&val, memPtr, 1);
    return val;
}
uint64_t xxread32(const void* memPtr)
{
    uint32_t val;
    memcpy(&val, memPtr, 4);
    return val;
}
uint64_t xxread64(const void* memPtr)
{
    uint64_t val;
    memcpy(&val, memPtr, 8);
    return val;
}
uint64_t XXH_rotl64(uint64_t x, int r)
{
    return ((x << r) | (x >> (64 - r)));
}
uint64_t XXHash(const uint8_t* input, size_t len)
{
    uint64_t h64;
    const uint8_t* bEnd = input + len;

    if (len >= 32) {
        const uint8_t* const limit = bEnd - 32;
        uint64_t v1 = PRIME1 + PRIME2;
        uint64_t v2 = PRIME2;
        uint64_t v3 = 0;
        uint64_t v4 = 0 - PRIME1;

        do
        {
            v1 += xxread64(input) * PRIME2;
            v1 = XXH_rotl64(v1, 31);
            v1 *= PRIME1;
            input += 8;
            v2 += xxread64(input) * PRIME2;
            v2 = XXH_rotl64(v2, 31);
            v2 *= PRIME1;
            input += 8;
            v3 += xxread64(input) * PRIME2;
            v3 = XXH_rotl64(v3, 31);
            v3 *= PRIME1;
            input += 8;
            v4 += xxread64(input) * PRIME2;
            v4 = XXH_rotl64(v4, 31);
            v4 *= PRIME1;
            input += 8;
        } while (input <= limit);

        h64 = XXH_rotl64(v1, 1) + XXH_rotl64(v2, 7) + XXH_rotl64(v3, 12) + XXH_rotl64(v4, 18);

        v1 *= PRIME2;
        v1 = XXH_rotl64(v1, 31);
        v1 *= PRIME1;
        h64 ^= v1;
        h64 = h64 * PRIME1 + PRIME4;

        v2 *= PRIME2;
        v2 = XXH_rotl64(v2, 31);
        v2 *= PRIME1;
        h64 ^= v2;
        h64 = h64 * PRIME1 + PRIME4;

        v3 *= PRIME2;
        v3 = XXH_rotl64(v3, 31);
        v3 *= PRIME1;
        h64 ^= v3;
        h64 = h64 * PRIME1 + PRIME4;

        v4 *= PRIME2;
        v4 = XXH_rotl64(v4, 31);
        v4 *= PRIME1;
        h64 ^= v4;
        h64 = h64 * PRIME1 + PRIME4;
    }
    else {
        h64 = PRIME5;
    }

    h64 += (uint64_t)len;

    while (input + 8 <= bEnd)
    {
        uint64_t k1 = xxread64(input);
        k1 *= PRIME2;
        k1 = XXH_rotl64(k1, 31);
        k1 *= PRIME1;
        h64 ^= k1;
        h64 = XXH_rotl64(h64, 27) * PRIME1 + PRIME4;
        input += 8;
    }

    if (input + 4 <= bEnd)
    {
        h64 ^= (uint64_t)(xxread32(input)) * PRIME1;
        h64 = XXH_rotl64(h64, 23) * PRIME2 + PRIME3;
        input += 4;
    }

    while (input < bEnd)
    {
        h64 ^= xxread8(input) * PRIME5;
        h64 = XXH_rotl64(h64, 11) * PRIME1;
        input += 1;
    }

    h64 ^= h64 >> 33;
    h64 *= PRIME2;
    h64 ^= h64 >> 29;
    h64 *= PRIME3;
    h64 ^= h64 >> 32;
    return h64;
}
uint32_t FNV1Hash(char* str)
{
    size_t Hash = 0x811c9dc5;
    for (size_t i = 0; i < strlen(str); i++)
        Hash = (Hash ^ tolower(str[i])) * 0x01000193;
    return Hash;
}
typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;
uint32_t ROTRIGHT(uint32_t x, int r)
{
    return ((x >> r) | (x << (32 - r)));
}
static const uint32_t k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
void sha256_transform(SHA256_CTX* ctx, const uint8_t data[])
{
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    for (; i < 64; ++i)
        m[i] = (ROTRIGHT(m[i - 2], 17) ^ ROTRIGHT(m[i - 2], 19) ^ (m[i - 2] >> 10))
        + m[i - 7] + (ROTRIGHT(m[i - 15], 7) ^ ROTRIGHT(m[i - 15], 18) ^ (m[i - 15] >> 3)) + m[i - 16];

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + (ROTRIGHT(e, 6) ^ ROTRIGHT(e, 11) ^ ROTRIGHT(e, 25)) + ((e & f) ^ (~e & g)) + k[i] + m[i];
        t2 = (ROTRIGHT(a, 2) ^ ROTRIGHT(a, 13) ^ ROTRIGHT(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}
void sha256_update(SHA256_CTX* ctx, const uint8_t data[], size_t len)
{
    for (uint32_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}
uint8_t* sha256_final(SHA256_CTX* ctx)
{
    uint32_t i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56)
            ctx->data[i++] = 0x00;
    }
    else {
        ctx->data[i++] = 0x80;
        while (i < 64)
            ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += (uint64_t)(ctx->datalen * 8);
    ctx->data[63] = (uint8_t)ctx->bitlen;
    ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
    ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
    ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
    ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
    ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
    ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
    ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
    sha256_transform(ctx, ctx->data);

    uint8_t* hash = (uint8_t*)malloc(8);
    for (i = 0; i < 4; ++i) {
        hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
    }
    return hash;
}
uint8_t* SHA256(const uint8_t data[], size_t len)
{
    SHA256_CTX* ctx = (SHA256_CTX*)calloc(1, sizeof(SHA256_CTX));
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    sha256_update(ctx, data, len);
    return sha256_final(ctx);
}

struct nodevoid
{
    void* value;
    uint64_t key;
    struct nodevoid* next;
};
typedef struct HashTableVoid
{
    uint64_t size;
    struct nodevoid** list;
} HashTableVoid;
HashTableVoid* createHashTableVoid(size_t size)
{
    HashTableVoid* t = (HashTableVoid*)malloc(sizeof(HashTableVoid));
    t->size = size;
    t->list = (struct nodevoid**)calloc(size, sizeof(struct nodevoid*));
    return t;
}
void insertHashTableVoid(HashTableVoid* t, uint64_t key, void* val)
{
    uint64_t pos = key % t->size;
    struct nodevoid* list = t->list[pos];
    struct nodevoid* temp = list;
    while (temp) {
        if (temp->key == key) {
            temp->value = val;
            return;
        }
        temp = temp->next;
    }
    struct nodevoid* newNode = (struct nodevoid*)malloc(sizeof(struct nodevoid));
    newNode->key = key;
    newNode->value = val;
    newNode->next = list;
    t->list[pos] = newNode;
}
void* lookupHashTableVoid(HashTableVoid* t, uint64_t key)
{
    struct nodevoid* list = t->list[key % t->size];
    struct nodevoid* temp = list;
    while (temp) {
        if (temp->key == key) {
            return temp->value;
        }
        temp = temp->next;
    }
    return NULL;
}

typedef struct nameid
{
    char* name;
    char* alias;
    uint32_t id;
} nameid;
typedef struct skinsid
{
    char* nameone;
    char* nametwo;
} skinsid;
typedef struct skinsname
{
    uint32_t size;
    skinsid** names;
} skinsname;
typedef struct FileHeader
{
    uint64_t PathHash;
    uint32_t Offset;
    uint32_t CompressedSize;
    uint32_t FileSize;
    uint8_t Type;
    uint8_t Duplicate;
    uint16_t Unknown;
    uint64_t SHA256;
    char* NewData;
} FileHeader;

void memfread(void* buf, size_t bytes, char** membuf)
{
    memcpy(buf, *membuf, bytes);
    *membuf += bytes;
}
char* extractdata(char* champpath, uint64_t hash, HashTableVoid* hasht, FILE* fp, uint8_t* type)
{
    if(hash == NULL)
        hash = XXHash(champpath, strlen(champpath));
    FileHeader* fh = (FileHeader*)lookupHashTableVoid(hasht, hash);
    char* data = (char*)malloc(fh->FileSize);
    if (type != NULL)
        *type = fh->Type;
    fseek(fp, fh->Offset, SEEK_SET);
    switch (fh->Type)
    {
        case 0:
            fread(data, fh->FileSize, 1, fp);
            break;
        case 1:
        {
            char* compresseddata = (char*)malloc(fh->CompressedSize);
            fread(compresseddata, fh->CompressedSize, 1, fp);
            int error = uncompress(data, (uLongf)fh->FileSize, compresseddata, fh->CompressedSize);
            if (error != Z_OK)
                printf("%s\n", zError(error));
            free(compresseddata);
            break;
        }
        case 2:
            printf("ERROR REDIRECTION TYPE NOT IMPLEMENTED 1\n");
            break;
        case 3:
        {
            char* compresseddata = (char*)malloc(fh->CompressedSize);
            fread(compresseddata, fh->CompressedSize, 1, fp);
            size_t error = ZSTD_decompress(data, fh->FileSize, compresseddata, fh->CompressedSize);
            if (ZSTD_isError(error))
                printf("%s\n", ZSTD_getErrorName(error));
            free(compresseddata);
            break;
        }
    }
    return data;
}
char* compressdata(char* data, uint8_t type, uint32_t siz, uint32_t* osize)
{
    char* datae = NULL;
    switch (type)
    {
        case 0:
            datae = data;
            break;
        case 1:
        {
            uLongf asize = compressBound(siz);
            datae = (char*)malloc(asize);
            *osize = compress(datae, &asize, data, siz);
            free(data);
            break;
        }
        case 2:
            printf("ERROR REDIRECTION TYPE NOT IMPLEMENTED 2\n");
            break;
        case 3:
        {
            size_t asize = ZSTD_compressBound(siz);
            datae = (char*)malloc(asize);
            *osize = ZSTD_compress(datae, asize, data, siz, 3);
            free(data);
            break;
        }
    }
    return datae;
}
char* binmod(char* champpath, HashTableVoid* hasht, FILE* fp, uint8_t* type, uint32_t* offset, char* name, char* change)
{
    *offset = 12;
    change[0] = toupper(change[0]);
    char* data = extractdata(champpath, NULL, hasht, fp, type) + 8;
    uint32_t linkedFilesCount = 0;
    memfread(&linkedFilesCount, 4, &data);
    uint16_t stringlength = 0;
    for (uint32_t i = 0; i < linkedFilesCount; i++)
    {
        memfread(&stringlength, 2, &data);
        data += stringlength;
        *offset += stringlength + 2;
    }
    uint32_t entryCount = 0;
    memfread(&entryCount, 4, &data);
    uint32_t* entryTypes = (uint32_t*)calloc(entryCount, 4);
    memfread(entryTypes, entryCount * 4, &data);
    *offset += entryCount * 4 + 4;
    for (size_t i = 0; i < entryCount; i++)
    {
        uint32_t entryLength = 0;
        memfread(&entryLength, 4, &data);
        uint32_t entryKeyHash = 0;
        memfread(&entryKeyHash, 4, &data);
        data -= 4;
        if (entryTypes[i] == 0x9B67E9F6 || entryTypes[i] == 0xF5FB07C7)
        {
            char* animpro = (char*)calloc(128, 1);
            snprintf(animpro, 128, "Characters/%s/Animations/%s", name, change);
            if (entryKeyHash == FNV1Hash(animpro))
            {
                char* skinpro = (char*)calloc(128, 1);
                snprintf(skinpro, 128, "Characters/%s/Animations/Skin0", name);
                entryKeyHash = FNV1Hash(skinpro);
                memcpy(data, &entryKeyHash, 4);
            }
            else
            {
                char* skinpro = (char*)calloc(128, 1);
                snprintf(skinpro, 128, "Characters/%s/Skins/Skin0", name);
                entryKeyHash = FNV1Hash(skinpro);
                memcpy(data, &entryKeyHash, 4);
            }
        }
        else if (entryTypes[i] == 0xEF3A0F33)
        {
            char* skinpro = (char*)calloc(128, 1);
            snprintf(skinpro, 128, "Characters/%s/Skins/Skin0/Resources", name);
            entryKeyHash = FNV1Hash(skinpro);
            memcpy(data, &entryKeyHash, 4);
        }
        data += entryLength;
        *offset += entryLength + 4;
    }
    change[0] = tolower(change[0]);
    data -= *offset;
    return data;
}

BOOL directoryexist(LPCTSTR szPath)
{
    DWORD dwAttrib = GetFileAttributesA(szPath);
    return (dwAttrib != INVALID_FILE_ATTRIBUTES && (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}
void createfolder(char* dirname)
{
    char* p;
    char* temp = calloc(strlen(dirname) + 1, 1);
    if ((p = strchr(dirname, ':')) != NULL) 
        p++;
    else
        p = dirname;

    while ((p = strchr(p, '\\')) != NULL) {
        if (p != dirname && *(p - 1) == '\\') {
            p++;
            continue;
        }
        memcpy(temp, dirname, p - dirname);
        temp[p - dirname] = '\0';
        p++;
        if (CreateDirectoryA(temp, NULL) == FALSE)
            if (GetLastError() != ERROR_ALREADY_EXISTS)
                break;
    }
    free(temp);
}
int strcicmp(char* a, char* b)
{
    for (;; a++, b++) {
        int d = tolower(*a) - tolower(*b);
        if (d != 0 || !*a)
            return d;
    }
}

int main(int argc, char** argv)
{
    setlocale(LC_ALL, "");
    char* overlay = (char*)calloc(256, 1);
    strcat_s(overlay, 256, argv[0]);
    char* overlaypos = strrchr(overlay, '\\');
    overlay[overlaypos-overlay] = '\0';
    strcat_s(overlay, 256, "\\Overlay\\");
    char* pathfile = (char*)calloc(256, 1);
    sprintf(pathfile, "%sDATA\\FINAL\\Champions\\", overlay);
    if(directoryexist(pathfile) == FALSE)
        createfolder(pathfile);
    for (size_t i = 0; i < strlen(overlay); i++)
        if (overlay[i] == '\\')
            overlay[i] = '/';

    HANDLE ThreadHandle = CreateThread(NULL, 0, modskin, overlay, 0, NULL);
    if (ThreadHandle == INVALID_HANDLE_VALUE || ThreadHandle == NULL)
    {
        printf("Failed to CreateThread: %d.\n", GetLastError());
        scanf("press enter to exit.");
        return 1;
    }

    printf("Waiting league client.\n");
    Process* process = ProcessFind("LeagueClient.exe");
    printf("League client found.\n");
    char* leaguedir = (char*)calloc(256, 1);
    strcat_s(leaguedir, 256, process->filepath);
    char* leaguedirpos = strrchr(leaguedir, '\\');
    leaguedir[leaguedirpos-leaguedir] = '\0';
    for (size_t i = 0; i < strlen(leaguedir); i++)
        if (leaguedir[i] == '\\')
            leaguedir[i] = '/';
    char* lockfiledir = (char*)calloc(256, 1);
    snprintf(lockfiledir, 256, "%s/lockfile", leaguedir);
    FILE* lockfile = fopen(lockfiledir, "rb");
    fseek(lockfile, 0, SEEK_END);
    long fsize = ftell(lockfile);
    fseek(lockfile, 0, SEEK_SET);
    char* lockstr = (char*)malloc(fsize + 1);
    fread(lockstr, fsize, 1, lockfile);
    lockstr[fsize] = '\0';
    fclose(lockfile);
    char* delim = ":";
    strtok(lockstr, delim);
    strtok(NULL, delim);
    char* port = strtok(NULL, delim);
    char* password = strtok(NULL, delim);
    char* protocol = strtok(NULL, delim);
    char* passauth = (char*)calloc(128, 1);
    sprintf(passauth, "riot:%s", password);
    char* auth = base64_encode(passauth, strlen(passauth));

    char* locale = download_url("/riotclient/region-locale", port, auth, protocol);
    cJSON* localejson = cJSON_ParseWithLength(locale, strlen(locale));
    char* region = (char*)cJSON_GetObjectItem(localejson, "locale")->value;

    cJSON* objd;
    char* catalog = download_url("/lol-store/v1/catalog?inventoryType=[\"CHAMPION_SKIN\",\"CHROMA_BUNDLE\"]", port, auth, protocol);
    cJSON* catalogjson = cJSON_ParseWithLength(catalog, strlen(catalog));
    HashTableVoid* hashc = createHashTableVoid(cJSON_GetArraySize(catalogjson));
    for (objd = catalogjson->child; objd != NULL; objd = objd->next)
    {
        uint64_t key = *(uint64_t*)cJSON_GetObjectItem(objd, "itemId")->value;
        cJSON* loca = cJSON_GetObjectItem(cJSON_GetObjectItem(objd, "localizations"), region);
        insertHashTableVoid(hashc, key, cJSON_GetObjectItem(loca, "name")->value);
    }

    int i = 0;
    char* champsummary = download_url("/lol-game-data/assets/v1/champion-summary.json", port, auth, protocol);
    cJSON* jsond = cJSON_ParseWithLength(champsummary, strlen(champsummary));
    size_t sized = cJSON_GetArraySize(jsond) - 1;
    nameid** nameida = (nameid**)malloc(sizeof(nameid*) * sized);
    for (objd = jsond->child; objd != NULL; objd = objd->next)
    {
        nameid* nameide = (nameid*)malloc(sizeof(nameid));
        nameide->id = *(uint32_t*)cJSON_GetObjectItem(objd, "id")->value;
        nameide->name = (char*)cJSON_GetObjectItem(objd, "name")->value;
        nameide->alias = (char*)cJSON_GetObjectItem(objd, "alias")->value;
        nameida[i++] = nameide;
    }

    char* skins = download_url("/lol-game-data/assets/v1/skins.json", port, auth, protocol);
    cJSON* jsone = cJSON_ParseWithLength(skins, strlen(skins));
    skinsname** sknn = (skinsname**)calloc(sized, sizeof(skinsname*));
    for (size_t i = 0; i < sized; i++)
    {
        int ik = 0;
        sknn[i] = (skinsname*)calloc(1, sizeof(skinsname));
        sknn[i]->names = (skinsid**)calloc(1, sizeof(skinsid*));
        for (int k = 1; k < 100; k++)
        {
            char* index = (char*)calloc(16, 1);
            snprintf(index, 16, "%d%03d", nameida[i]->id, k);
            cJSON* var = cJSON_GetObjectItem(jsone, index);
            if (var == NULL)
                continue;
            sknn[i]->size += 1;            
            uint32_t ide = *(uint32_t*)cJSON_GetObjectItem(var, "id")->value;
            sknn[i]->names = (skinsid**)realloc(sknn[i]->names, sknn[i]->size * sizeof(skinsid*));
            sknn[i]->names[ik] = (skinsid*)calloc(1, sizeof(skinsid));
            sknn[i]->names[ik]->nameone = cJSON_GetObjectItem(var, "name")->value;
            sknn[i]->names[ik]->nametwo = (char*)calloc(16, 1);
            snprintf(sknn[i]->names[ik++]->nametwo, 16, "skin%d", ide % 100);
            cJSON* chr = cJSON_GetObjectItem(var, "chromas");
            if (chr != NULL)
            {
                for (objd = chr->child; objd != NULL; objd = objd->next)
                {
                    uint32_t id = *(uint32_t*)cJSON_GetObjectItem(objd, "id")->value;
                    char* name = (char*)lookupHashTableVoid(hashc, id);
                    if (name != NULL)
                    {
                        sknn[i]->size += 1;
                        sknn[i]->names = (skinsid**)realloc(sknn[i]->names, sknn[i]->size * sizeof(skinsid*));
                        sknn[i]->names[ik] = (skinsid*)calloc(1, sizeof(skinsid));
                        sknn[i]->names[ik]->nameone = name;
                        sknn[i]->names[ik]->nametwo = (char*)calloc(16, 1);
                        snprintf(sknn[i]->names[ik++]->nametwo, 16, "skin%d", id % 100);
                    }
                }
            }
        }
    }

    uint16_t MajorMinor = 3;
    uint16_t Signature = 22354;
    char* lower = (char*)calloc(32, 1);
    char* nulls = (char*)calloc(264, 1);
    char* Champion = (char*)calloc(32, 1);
    char* FileName = (char*)calloc(256, 1);
    char* champpath = (char*)calloc(128, 1);
    char* fileFound = (char*)calloc(256, 1);
    while (1)
    {
        printf("Type champion name or exit to exit: ");
        scanf("%s", Champion);
        if (strcmp(Champion, "exit") == 0)
            break;

        int choose = -1;
        for (size_t i = 0; i < sized; i++)
        {
            if (strcicmp(Champion, nameida[i]->name) == 0 || strcicmp(Champion, nameida[i]->alias) == 0)
            {
                choose = i;
                break;
            }
        }
        if (choose == -1)
        {
            printf("Champion not found, try again.\n");
            continue;
        }

        for (int i = 0; i < nameida[choose]->alias[i]; i++)
            lower[i] = tolower(nameida[choose]->alias[i]);

        snprintf(FileName, 256, "%s/Game/DATA/FINAL/Champions/%s.wad.client", leaguedir, nameida[choose]->alias);
        FILE* filew = fopen(FileName, "rb");

        fseek(filew, 268, SEEK_SET);
        uint32_t fileCount = 0;
        fread(&fileCount, 4, 1, filew);
        HashTableVoid* hasht = createHashTableVoid(fileCount);
        FileHeader** fharryb = (FileHeader**)malloc(sizeof(FileHeader*) * fileCount);
        for (uint32_t i = 0; i < fileCount; i++)
        {
            fharryb[i] = (FileHeader*)calloc(1, sizeof(FileHeader));
            FileHeader* ori = (FileHeader*)calloc(1, sizeof(FileHeader));
            fread(ori, 32, 1, filew);
            memcpy(fharryb[i], ori, 32);
            insertHashTableVoid(hasht, ori->PathHash, ori);
        }

        uint32_t offsetwad = 0;
        uint8_t retbreak = 0, foundname = 0;
        size_t sizechamp = 0, indexchamp = 0;
        skinsid** nameschamp = (skinsid**)calloc(1, 1);
        for (uint32_t i = 0; i < fileCount; i++)
        {
            if (fharryb[i]->Type != 2)
            {
                offsetwad = 4;
                uint32_t Signaturee = 0;
                char* data = extractdata("", fharryb[i]->PathHash, hasht, filew, NULL);
                memfread(&Signaturee, 4, &data);
                if (memcmp(&Signaturee, "PROP", 4) == 0)
                {
                    retbreak = 0;
                    uint32_t Version = 0;
                    memfread(&Version, 4, &data);
                    if (Version >= 2)
                    {
                        offsetwad += 4;
                        uint32_t linkedFilesCount = 0;
                        memfread(&linkedFilesCount, 4, &data);
                        uint16_t stringlength = 0;
                        for (uint32_t k = 0; k < linkedFilesCount; k++)
                        {
                            memfread(&stringlength, 2, &data);
                            data += stringlength;
                            offsetwad += stringlength + 2;
                        }
                    }
                    uint32_t entryCount = 0;
                    memfread(&entryCount, 4, &data);
                    uint32_t* entryTypes = (uint32_t*)calloc(entryCount, 4);
                    memfread(entryTypes, entryCount * 4, &data);
                    offsetwad += 8 + entryCount * 4;
                    for (size_t l = 0; l < entryCount; l++)
                    {
                        uint32_t entryLength = 0;
                        memfread(&entryLength, 4, &data);
                        uint32_t entryKeyHash = 0;
                        memfread(&entryKeyHash, 4, &data);
                        uint16_t fieldcount = 0;
                        memfread(&fieldcount, 2, &data);
                        for (uint16_t k = 0; k < fieldcount; k++)
                        {
                            offsetwad += 5;
                            entryLength -= 5;
                            uint32_t name = 0;
                            memfread(&name, 4, &data);
                            uint8_t type = 0;
                            memfread(&type, 1, &data);
                            if (name == 762889000UL && type == 16)
                            {
                                foundname = 0;
                                uint16_t stringlength = 0;
                                memfread(&stringlength, 2, &data);
                                char* namestring = (char*)calloc(stringlength + 1, 1);
                                memfread(namestring, (size_t)stringlength, &data);
                                namestring[stringlength] = '\0';
                                entryLength -= 2 + stringlength;
                                offsetwad += 2 + stringlength;
                                char* pointer = strstr(namestring, "Base");
                                if(pointer == NULL)
                                    pointer = strstr(namestring, "Skin");
                                if (pointer != NULL)
                                {
                                    namestring[pointer-namestring] = '\0';
                                    size_t namesize = strlen(namestring);
                                    char* namestringup = (char*)malloc(namesize);
                                    memcpy(namestringup, namestring, namesize);
                                    namestringup[namesize] = '\0';
                                    for (size_t o = 0; o < namestring[o]; o++)
                                        namestring[o] = tolower(namestring[o]);
                                    for (size_t o = 0; o < sizechamp; o++)
                                        if (strcmp(nameschamp[o]->nameone, namestring) == 0)
                                            foundname = 1;
                                    if (!foundname)
                                    {
                                        snprintf(champpath, 128, "data/characters/%s/skins/skin0.bin", namestring);
                                        if (lookupHashTableVoid(hasht, XXHash(champpath, strlen(champpath))) != NULL)
                                        {
                                            sizechamp += 1;
                                            nameschamp = (skinsid**)realloc(nameschamp, sizechamp * sizeof(skinsid*));
                                            nameschamp[indexchamp] = (skinsid*)malloc(sizeof(skinsid));
                                            nameschamp[indexchamp]->nameone = namestring;
                                            nameschamp[indexchamp]->nametwo = namestringup;
                                            indexchamp += 1;
                                            retbreak = 1;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        data += entryLength - 6;
                        offsetwad += entryLength + 4;
                        if (retbreak)
                            break;
                    }
                } 
                data -= offsetwad;
                free(data);
            }
        }

        foundname = 0;
        for (size_t i = 0; i < sizechamp; i++)
            if (strcmp(nameschamp[i], lower) == 0)
                foundname = 1;
        if (!foundname)
        {
            sizechamp += 1;
            nameschamp = (skinsid**)realloc(nameschamp, sizechamp * sizeof(skinsid*));
            nameschamp[indexchamp] = (skinsid*)malloc(sizeof(skinsid));
            nameschamp[indexchamp]->nameone = lower;
            nameschamp[indexchamp]->nametwo = nameida[choose]->alias;
        }

        WIN32_FIND_DATA info;
        sprintf(fileFound, "%sDATA/FINAL/Champions/*.*", overlay);
        HANDLE hp = FindFirstFileA(fileFound, &info);
        do
        {
            sprintf(fileFound, "%sDATA/FINAL/Champions/%s", overlay, info.cFileName);
            DeleteFileA(fileFound);

        } while (FindNextFileA(hp, &info));
        FindClose(hp);

        for (uint32_t k = 0; k < sknn[choose]->size; k++)
            printf("%d: %s\n", k + 1, sknn[choose]->names[k]->nameone);

        uint8_t num = 0;
        uint8_t type = 1;
        uint32_t offsete = 0;
        uint64_t hashindex = 0;
        FileHeader* fhpointer = fharryb[0];
        char* nullse = (char*)calloc(fileCount, 32);
        FileHeader** fharry = (FileHeader**)malloc(sizeof(FileHeader*) * fileCount);
        while (1)
        {
            printf("Type skin number or 0 to exit: ");
            scanf("%hhu", &num);
            if (num == 0)
                break;
            else if (num > sknn[choose]->size)
            {
                printf("Skin number not found, try again.\n");
                continue;
            }

            for (uint32_t i = 0; i < fileCount; i++)
            {
                fharry[i] = (FileHeader*)calloc(1, sizeof(FileHeader));
                memcpy(fharry[i], fharryb[i], 32);
            }

            for (size_t i = 0; i < sizechamp; i++)
            {
                snprintf(champpath, 128, "data/characters/%s/skins/skin0.bin", nameschamp[i]->nameone);
                hashindex = XXHash(champpath, strlen(champpath));
                for (uint32_t i = 0; i < fileCount; i++)
                {
                    if (fharry[i]->PathHash == hashindex)
                    {
                        fhpointer = fharry[i];
                        break;
                    }
                }
                snprintf(champpath, 128, "data/characters/%s/skins/%s.bin", nameschamp[i]->nameone, sknn[choose]->names[num-1]->nametwo);
                char* dataskin = binmod(champpath, hasht, filew, &type, &offsete, nameschamp[i]->nametwo, sknn[choose]->names[num-1]->nametwo);
                fhpointer->NewData = compressdata(dataskin, type, offsete, &fhpointer->CompressedSize);
                memcpy(&fhpointer->SHA256, SHA256(fhpointer->NewData, fhpointer->CompressedSize), 8);
                fhpointer->FileSize = offsete;

                snprintf(champpath, 128, "data/characters/%s/animations/skin0.bin", nameschamp[i]->nameone);
                hashindex = XXHash(champpath, strlen(champpath));
                for (uint32_t i = 0; i < fileCount; i++)
                {
                    if (fharry[i]->PathHash == hashindex)
                    {
                        fhpointer = fharry[i];
                        break;
                    }
                }
                snprintf(champpath, 128, "data/characters/%s/animations/%s.bin", nameschamp[i]->nameone, sknn[choose]->names[num-1]->nametwo);
                char* dataanm = binmod(champpath, hasht, filew, &type, &offsete, nameschamp[i]->nametwo, sknn[choose]->names[num-1]->nametwo);
                fhpointer->NewData = compressdata(dataanm, type, offsete, &fhpointer->CompressedSize);
                memcpy(&fhpointer->SHA256, SHA256(fhpointer->NewData, fhpointer->CompressedSize), 8);
                fhpointer->FileSize = offsete;
            }

            snprintf(FileName, 256, "%sDATA/FINAL/Champions/%s.wad.client", overlay, nameida[choose]->alias);
            FILE* filem = fopen(FileName, "wb");

            fwrite(&Signature, 2, 1, filem);
            fwrite(&MajorMinor, 2, 1, filem);
            fwrite(nulls, 1, 264, filem);
            fwrite(&fileCount, 4, 1, filem);
            fwrite(nullse, 32, fileCount, filem);

            for (uint32_t i = 0; i < fileCount; i++)
            {
                fharry[i]->Duplicate = 0;
                FileHeader* duplicatedEntry = NULL;
                for (uint32_t j = 0; j < i; j++)
                {
                    if (memcmp(&fharry[j]->SHA256, &fharry[i]->SHA256, 8) == 0)
                    {
                        fharry[i]->Duplicate = 1;
                        duplicatedEntry = fharry[j];
                        break;
                    }
                }
                if (duplicatedEntry == NULL)
                {
                    uint32_t off = ftell(filem);
                    if (fharry[i]->NewData == NULL)
                    {
                        char* data = (char*)malloc(fharry[i]->CompressedSize);
                        fseek(filew, fharry[i]->Offset, SEEK_SET);
                        fread(data, 1, fharry[i]->CompressedSize, filew);
                        fwrite(data, 1, fharry[i]->CompressedSize, filem);
                        free(data);
                    }
                    else
                    {
                        fwrite(fharry[i]->NewData, 1, fharry[i]->CompressedSize, filem);
                        free(fharry[i]->NewData);
                    }
                    fharry[i]->Offset = off;
                }
                else
                {
                    fharry[i]->Offset = duplicatedEntry->Offset;
                }
            }

            fseek(filem, 272, SEEK_SET);
            for (uint32_t i = 0; i < fileCount; i++)
                fwrite(fharry[i], 32, 1, filem);
            fclose(filem);

            for (uint32_t i = 0; i < fileCount; i++)
                free(fharry[i]);
        }
        fclose(filew);
        memset(lower, 0, 32);
    }
    CloseHandle(ThreadHandle);
    return 0;
}