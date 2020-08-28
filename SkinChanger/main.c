#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <Windows.h>
#include <direct.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include "cJSON.h"
#include "../libs/zlib.h"
#include "../libs/zstd.h"

typedef struct Process
{
    HANDLE handle;
    DWORD baselength;
    DWORD baseaddress;
} Process;
static DWORD PROCESS_NEEDED_ACCESS = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | SYNCHRONIZE;
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
                            process->baselength = mEntry.modBaseSize;
                            process->baseaddress = (DWORD)mEntry.hModule;
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
DWORD AllocateMemory(HANDLE handle, DWORD size)
{
    DWORD ptr = VirtualAllocEx(handle, 0, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (ptr == 0)
        printf("\nFailed to allocate memory\n");
    return ptr;
}
uint8_t* ReadMemory(HANDLE handle, DWORD address, DWORD size)
{
    uint8_t* buffer = (uint8_t*)malloc(size);
    if (!ReadProcessMemory(handle, address, buffer, size, NULL))
    {
        printf("\nFailed to read memory: %u\n", address);
        return 0;
    }
    return buffer;
}
uint8_t WriteMemory(HANDLE handle, DWORD address, uint8_t* buffer, DWORD length)
{
    if (!WriteProcessMemory(handle, address, buffer, length, NULL))
    {
        printf("\nFailed to write memory: %u\n", address);
        return 0;
    }
    return 1;
}
uint8_t MarkMemoryExecutable(HANDLE handle, DWORD address, DWORD size)
{
    DWORD old = 0;
    if (!VirtualProtectEx(handle, address, size, PAGE_EXECUTE, &old))
    {
        printf("\nFailed to mark region as executable: %u\n", address);
        return 0;
    }
    return 1;
}
DWORD WaitPointerNonZero(HANDLE handle, DWORD address)
{
    uint32_t buffer;
    do
    {
        Sleep(1);
        if (!ReadProcessMemory(handle, address, &buffer, 4, NULL))
        {
            printf("\nFailed to wait pointer non zero: %u\n", address);
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
DWORD WINAPI modskin(LPVOID Param)
{
    uint8_t* fpmask = "xxxxxx????xxxxxx";
    uint8_t* pmethmask = "x????xxxxxxx?x????xx????xxxxx";
    uint8_t* fpsignature = "\x56\x8B\x74\x24\x08\xB8\x99\x99\x99\x99\x33\xC9\x0F\x1F\x40\x00";
    uint8_t* pmethsignature = "\x68\x99\x99\x99\x99\x6A\x04\x6A\x12\x8D\x44\x24\x99\x68\x99\x99\x99\x99\x50\xE8\x99\x99\x99\x99\x83\xC4\x14\x85\xC0";
    uint8_t codeVerify[0x10] = {
        0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    };
    uint8_t PrefixFn[0x30] = {
        0x57, 0x56, 0x8b, 0x54, 0x24, 0x0c, 0x8b, 0x74, 0x24, 0x14, 0x89, 0xd7,
        0xac, 0xaa, 0x84, 0xc0, 0x75, 0xfa, 0x8b, 0x74, 0x24, 0x10, 0x83, 0xef,
        0x01, 0xac, 0xaa, 0x84, 0xc0, 0x75, 0xfa, 0x5e, 0x89, 0xd0, 0x5f, 0xc3,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    };
    uint8_t Open[0x50] = {
        0x56, 0x53, 0x81, 0xec, 0x14, 0x02, 0x00, 0x00, 0x8b, 0x41, 0x04, 0x8b, 0x58, 0x08,
        0x8b, 0x03, 0x8b, 0x30, 0x8d, 0x41, 0x0c, 0x89, 0x44, 0x24, 0x08, 0x8b, 0x84, 0x24,
        0x20, 0x02, 0x00, 0x00, 0x89, 0x44, 0x24, 0x04, 0x8d, 0x44, 0x24, 0x10, 0x89, 0x04,
        0x24, 0xff, 0x51, 0x08, 0x8b, 0x94, 0x24, 0x24, 0x02, 0x00, 0x00, 0x89, 0xd9, 0x89,
        0x04, 0x24, 0x89, 0x54, 0x24, 0x04, 0xff, 0xd6, 0x83, 0xec, 0x08, 0x81, 0xc4, 0x14,
        0x02, 0x00, 0x00, 0x5b, 0x5e, 0xc2, 0x08, 0x00, 0x90, 0x90,
    };
    uint8_t CheckAccess[0x50] = {
        0x56, 0x53, 0x81, 0xec, 0x14, 0x02, 0x00, 0x00, 0x8b, 0x41, 0x04, 0x8b, 0x58, 0x08,
        0x8b, 0x03, 0x8b, 0x70, 0x04, 0x8d, 0x41, 0x0c, 0x89, 0x44, 0x24, 0x08, 0x8b, 0x84,
        0x24, 0x20, 0x02, 0x00, 0x00, 0x89, 0x44, 0x24, 0x04, 0x8d, 0x44, 0x24, 0x10, 0x89,
        0x04, 0x24, 0xff, 0x51, 0x08, 0x8b, 0x94, 0x24, 0x24, 0x02, 0x00, 0x00, 0x89, 0xd9,
        0x89, 0x04, 0x24, 0x89, 0x54, 0x24, 0x04, 0xff, 0xd6, 0x83, 0xec, 0x08, 0x81, 0xc4,
        0x14, 0x02, 0x00, 0x00, 0x5b, 0x5e, 0xc2, 0x08, 0x00, 0x90,
    };
    uint8_t CreateIterator[0x10] = {
        0x31, 0xc0, 0xc2, 0x08, 0x00, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    };
    uint8_t VectorDeleter[0x10] = {
        0x89, 0xc8, 0xc2, 0x04, 0x00, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    };
    uint8_t IsRads[0x10] = {
        0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    };
    while (1)
    {
        Process* process = ProcessFind("League of Legends.exe");
        WaitForInputIdle(process->handle, INFINITE);
        uint8_t* buffer = (uint8_t*)malloc(process->baselength);
        for (DWORD p = 0; p != process->baselength; p += 0x1000)
            ReadProcessMemory(process->handle, process->baseaddress + p, buffer + p, 0x1000, NULL);
        DWORD res_fp = FindAddress(fpsignature, fpmask, 16, buffer, process->baselength) + 6;
        DWORD res_pmeth = FindAddress(pmethsignature, pmethmask, 29, buffer, process->baselength) + 14;
        if (res_fp == 6 || res_pmeth == 14)
            printf("\nFailed to get offsets!\n");
        DWORD off_fp = *((DWORD*)(buffer + res_fp)) - process->baseaddress;
        DWORD off_pmeth = *((DWORD*)(buffer + res_pmeth)) - process->baseaddress;
        DWORD codePointer = AllocateMemory(process->handle, 0x900);
        assert(codePointer != 0);
        DWORD codeVerifyPointer = codePointer + 0x000;
        DWORD codePrefixFnPointer = codePointer + 0x100;
        DWORD codeOpenPointer = codePointer + 0x200;
        DWORD codeCheckAccessPointer = codePointer + 0x300;
        DWORD codeCreateIteratorPointer = codePointer + 0x400;
        DWORD codeVectorDeleterPointer = codePointer + 0x500;
        DWORD codeIsRadsPointer = codePointer + 0x600;
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
        DWORD orgignalPMethArrayPointer = off_pmeth + process->baseaddress;
        DWORD originalPMethFirstPointer = WaitPointerNonZero(process->handle, orgignalPMethArrayPointer);
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

    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
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
struct nodefh
{
    uint64_t key;
    FileHeader* value;
    struct nodefh* next;
};
typedef struct HashTablefh
{
    uint64_t size;
    struct nodefh** list;
} HashTablefh;
HashTablefh* createHashTablefh(size_t size)
{
    HashTablefh* t = (HashTablefh*)malloc(sizeof(HashTablefh));
    t->size = size;
    t->list = (struct node**)calloc(size, sizeof(struct node*));
    return t;
}
void insertHashTablefh(HashTablefh* t, uint64_t key, FileHeader* val)
{
    uint64_t pos = key % t->size;
    struct nodefh* list = t->list[pos];
    struct nodefh* temp = list;
    while (temp) {
        if (temp->key == key) {
            temp->value = val;
            return;
        }
        temp = temp->next;
    }
    struct nodefh* newNode = (struct nodefh*)malloc(sizeof(struct nodefh));
    newNode->key = key;
    newNode->value = val;
    newNode->next = list;
    t->list[pos] = newNode;
}
FileHeader* lookupHashTablefh(HashTablefh* t, uint64_t key)
{
    struct nodefh* list = t->list[key % t->size];
    struct nodefh* temp = list;
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

void memfread(void* buf, size_t bytes, char** membuf)
{
    memcpy(buf, *membuf, bytes);
    *membuf += bytes;
}
char* extractdata(char* champpath, HashTablefh* hasht, FILE* fp, uint8_t* type)
{
    uint64_t hash = XXHash(champpath, strlen(champpath));
    FileHeader* fh = lookupHashTablefh(hasht, hash);
    char* data = (char*)malloc(fh->FileSize);
    if (type != NULL)
        *type = fh->Type;
    fseek(fp, fh->Offset, SEEK_SET);
    switch (fh->Type)
    {
        case 0:
            printf("ERROR UNCOMPRESSED TYPE NOT IMPLEMENTED 1\n");
            break;
        case 1:
            printf("ERROR REDIRECTION TYPE NOT IMPLEMENTED 1\n");
            break;
        case 2:
        {
            char* compresseddata = (char*)malloc(fh->CompressedSize);
            fread(compresseddata, fh->CompressedSize, 1, fp);
            int error = uncompress(data, fh->FileSize, compresseddata, fh->CompressedSize);
            if (error != Z_OK)
                printf("%s\n", zError(error));
            break;
        }
        case 3:
        {
            char* compresseddata = (char*)malloc(fh->CompressedSize);
            fread(compresseddata, fh->CompressedSize, 1, fp);
            size_t error = ZSTD_decompress(data, fh->FileSize, compresseddata, fh->CompressedSize);
            if (ZSTD_isError(error))
                printf("%s\n", ZSTD_getErrorName(error));
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
            printf("ERROR UNCOMPRESSED TYPE NOT IMPLEMENTED 2\n");
            break;
        case 1:
            printf("ERROR REDIRECTION TYPE NOT IMPLEMENTED 2\n");
            break;
        case 2:
        {
            uLong asize = compressBound(siz);
            datae = (char*)malloc(asize);
            *osize = compress(datae, asize, data, siz);
            break;
        }
        case 3:
        {
            uLong asize = ZSTD_compressBound(siz);
            datae = (char*)malloc(asize);
            *osize = ZSTD_compress(datae, asize, data, siz, 3);
            break;
        }
    }
    return datae;
}
char* binmod(char* champpath, HashTablefh* hasht, FILE* fp, uint8_t* type, uint32_t* offset, char* name)
{
    *offset = 12;
    char* data = extractdata(champpath, hasht, fp, type) + 8;
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
        if (entryTypes[i] == 2607278582UL || entryTypes[i] == 4126869447UL)
        {
            char* skinpro = (char*)calloc(128, 1);
            snprintf(skinpro, 128, "Characters/%s/Skins/Skin0", name);
            entryKeyHash = FNV1Hash(skinpro);
            memcpy(data, &entryKeyHash, 4);
        }
        else if (entryTypes[i] == 4013559603UL)
        {
            char* skinpro = (char*)calloc(128, 1);
            snprintf(skinpro, 128, "Characters/%s/Skins/Skin0/Resources", name);
            entryKeyHash = FNV1Hash(skinpro);
            memcpy(data, &entryKeyHash, 4);
        }
        data += entryLength;
        *offset += entryLength + 4;
    }
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
    char* overlay = (char*)calloc(256, 1);
    strcat_s(overlay, 256, argv[0]);
    char* overlaypos = strrchr(overlay, '\\');
    overlay[overlaypos - overlay] = '\0';
    strcat_s(overlay, 256, "\\Overlay\\");
    char* pathfile = (char*)calloc(256, 1);
    sprintf(pathfile, "%sDATA\\FINAL\\Champions\\", overlay);
    if(directoryexist(pathfile) == FALSE)
        createfolder(pathfile);
    for (int i = 0; i < strlen(overlay); i++)
        if (overlay[i] == '\\')
            overlay[i] = '/';

    HANDLE ThreadHandle = CreateThread(NULL, 0, modskin, overlay, 0, NULL);
    FILE* filea = fopen("C:/Riot Games/League of Legends/Plugins/rcp-be-lol-game-data/default-assets.wad", "rb");

    fseek(filea, 268, SEEK_SET);
    uint32_t fileCounta = 0;
    fread(&fileCounta, 4, 1, filea);

    HashTablefh* hashte = createHashTablefh(fileCounta);
    for (uint32_t i = 0; i < fileCounta; i++)
    {
        FileHeader* fh = (FileHeader*)calloc(1, sizeof(FileHeader));
        fread(fh, 32, 1, filea);
        insertHashTablefh(hashte, fh->PathHash, fh);
    }
    char* sadae = "plugins/rcp-be-lol-game-data/global/default/v1/skins.json";
    char* sadad = "plugins/rcp-be-lol-game-data/global/default/v1/champion-summary.json";
    char* datae = extractdata(sadae, hashte, filea, NULL);
    char* datad = extractdata(sadad, hashte, filea, NULL);
    fclose(filea);

    int i = 0;
    cJSON* objd;
    cJSON* jsond = cJSON_ParseWithLength(datad, strlen(datad));
    size_t sized = cJSON_GetArraySize(jsond) - 1;
    nameid** nameida = (nameid**)malloc(sizeof(nameid*) * sized);
    for (objd = jsond->child->next; objd != NULL; objd = objd->next)
    {
        nameid* nameide = (nameid*)malloc(sizeof(nameid));
        nameide->id = *(uint32_t*)cJSON_GetObjectItem(objd, "id")->value;
        nameide->name = (char*)cJSON_GetObjectItem(objd, "name")->value;
        nameide->alias = (char*)cJSON_GetObjectItem(objd, "alias")->value;
        nameida[i++] = nameide;
    }

    cJSON* jsone = cJSON_ParseWithLength(datae, strlen(datae));
    skinsname** sknn = (skinsname**)malloc(sizeof(skinsname*) * sized);
    for (int i = 0; i < sized; i++)
    {
        int sizek = 1, ik = 0;
        sknn[i] = (skinsname*)malloc(sizeof(skinsname));
        for (int k = 1; k < 100; k++)
        {
            char* index = (char*)calloc(16, 1);
            snprintf(index, 16, "%d%03d", nameida[i]->id, k);
            if (cJSON_GetObjectItem(jsone, index) == NULL)
                continue;
            sizek++;
        }
        sknn[i]->size = sizek - 1;
        sknn[i]->names = (skinsid**)malloc(sizeof(skinsid*) * sizek);
        for (int k = 1; k < 100; k++)
        {
            char* index = (char*)calloc(16, 1);
            snprintf(index, 16, "%d%03d", nameida[i]->id, k);
            cJSON* var = cJSON_GetObjectItem(jsone, index);
            if (var == NULL)
                continue;
            sknn[i]->names[ik] = (skinsid*)malloc(sizeof(skinsid));
            sknn[i]->names[ik]->nameone = cJSON_GetObjectItem(var, "name")->value;
            sknn[i]->names[ik]->nametwo = (char*)calloc(16, 1);
            snprintf(sknn[i]->names[ik]->nametwo, 16, "skin%d", k);
            ik++;
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
        printf("type champion name or exit to exit: ");
        scanf("%s", Champion);
        if (strcmp(Champion, "exit") == 0)
            break;

        int choose = 0;
        for (int i = 0; i < sized; i++)
        {
            if (strcicmp(Champion, nameida[i]->name) == 0 || strcicmp(Champion, nameida[i]->alias) == 0)
            {
                choose = i;
                break;
            }
        }

        for (int i = 0; i < nameida[choose]->alias[i]; i++)
            lower[i] = tolower(nameida[choose]->alias[i]);

        snprintf(FileName, 256, "C:/Riot Games/League of Legends/Game/DATA/FINAL/Champions/%s.wad.client", nameida[choose]->alias);
        FILE* filew = fopen(FileName, "rb");

        fseek(filew, 268, SEEK_SET);
        uint32_t fileCount = 0;
        fread(&fileCount, 4, 1, filew);
        HashTablefh* hasht = createHashTablefh(fileCount);
        FileHeader** fharryb = (FileHeader**)malloc(sizeof(FileHeader*) * fileCount);
        for (uint32_t i = 0; i < fileCount; i++)
        {
            fharryb[i] = (FileHeader*)calloc(1, sizeof(FileHeader));
            FileHeader* ori = (FileHeader*)calloc(1, sizeof(FileHeader));
            fread(ori, 32, 1, filew);
            memcpy(fharryb[i], ori, 32);
            insertHashTablefh(hasht, ori->PathHash, ori);
        }

        for (int k = 0; k < sknn[choose]->size; k++)
            printf("%d: %s\n", k + 1, sknn[choose]->names[k]->nameone);

        WIN32_FIND_DATA info;
        sprintf(fileFound, "%sDATA/FINAL/Champions/*.*", overlay);
        HANDLE hp = FindFirstFileA(fileFound, &info);
        do
        {
            sprintf(fileFound, "%sDATA/FINAL/Champions/%s", overlay, info.cFileName);
            DeleteFileA(fileFound);

        } while (FindNextFileA(hp, &info));
        FindClose(hp);

        uint8_t type = 1;
        uint32_t num = 0;
        uint32_t offsete = 0;
        uint64_t hashindex = 0;
        FileHeader* fhpointer = fharryb[0];
        char* nullse = (char*)calloc(fileCount, 32);
        FileHeader** fharry = (FileHeader**)malloc(sizeof(FileHeader*) * fileCount);
        while (1)
        {
            printf("type skin number or 0 to exit: ");
            scanf("%lu", &num);
            if (num == 0)
                break;

            for (uint32_t i = 0; i < fileCount; i++)
            {
                fharry[i] = (FileHeader*)calloc(1, sizeof(FileHeader));
                memcpy(fharry[i], fharryb[i], 32);
            }

            snprintf(champpath, 128, "data/characters/%s/skins/skin0.bin", lower);
            hashindex = XXHash(champpath, strlen(champpath));
            for (uint32_t i = 0; i < fileCount; i++)
            {
                if (fharry[i]->PathHash == hashindex)
                {
                    fhpointer = fharry[i];
                    break;
                }
            }
            snprintf(champpath, 128, "data/characters/%s/skins/%s.bin", lower, sknn[choose]->names[num - 1]->nametwo);
            char* dataskin = binmod(champpath, hasht, filew, &type, &offsete, nameida[choose]->alias);
            fhpointer->NewData = compressdata(dataskin, type, offsete, &fhpointer->CompressedSize);
            memcpy(&fhpointer->SHA256, SHA256(fhpointer->NewData, fhpointer->CompressedSize), 8);
            fhpointer->FileSize = offsete;
            free(dataskin);

            snprintf(champpath, 128, "data/characters/%s/animations/skin0.bin", lower);
            hashindex = XXHash(champpath, strlen(champpath));
            for (uint32_t i = 0; i < fileCount; i++)
            {
                if (fharry[i]->PathHash == hashindex)
                {
                    fhpointer = fharry[i];
                    break;
                }
            }
            snprintf(champpath, 128, "data/characters/%s/animations/%s.bin", lower, sknn[choose]->names[num - 1]->nametwo);
            char* dataanm = binmod(champpath, hasht, filew, &type, &offsete, nameida[choose]->alias);
            fhpointer->NewData = compressdata(dataanm, type, offsete, &fhpointer->CompressedSize);
            memcpy(&fhpointer->SHA256, SHA256(fhpointer->NewData, fhpointer->CompressedSize), 8);
            fhpointer->FileSize = offsete;
            free(dataanm);

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