#if defined (__cplusplus)
extern "C" {
#endif

#ifndef ZSTD_H_235446
#define ZSTD_H_235446

#include <limits.h>     
#include <stddef.h>     


#ifndef ZSTDLIB_VISIBILITY
#  if defined(__GNUC__) && (__GNUC__ >= 4)
#    define ZSTDLIB_VISIBILITY __attribute__ ((visibility ("default")))
#  else
#    define ZSTDLIB_VISIBILITY
#  endif
#endif
#if defined(ZSTD_DLL_EXPORT) && (ZSTD_DLL_EXPORT==1)
#  define ZSTDLIB_API __declspec(dllexport) ZSTDLIB_VISIBILITY
#elif defined(ZSTD_DLL_IMPORT) && (ZSTD_DLL_IMPORT==1)
#  define ZSTDLIB_API __declspec(dllimport) ZSTDLIB_VISIBILITY                      
#else
#  define ZSTDLIB_API ZSTDLIB_VISIBILITY
#endif


#define ZSTD_VERSION_MAJOR    1
#define ZSTD_VERSION_MINOR    4
#define ZSTD_VERSION_RELEASE  5

#define ZSTD_VERSION_NUMBER  (ZSTD_VERSION_MAJOR *100*100 + ZSTD_VERSION_MINOR *100 + ZSTD_VERSION_RELEASE)
ZSTDLIB_API unsigned ZSTD_versionNumber(void);         

#define ZSTD_LIB_VERSION ZSTD_VERSION_MAJOR.ZSTD_VERSION_MINOR.ZSTD_VERSION_RELEASE
#define ZSTD_QUOTE(str) #str
#define ZSTD_EXPAND_AND_QUOTE(str) ZSTD_QUOTE(str)
#define ZSTD_VERSION_STRING ZSTD_EXPAND_AND_QUOTE(ZSTD_LIB_VERSION)
ZSTDLIB_API const char* ZSTD_versionString(void);      

#ifndef ZSTD_CLEVEL_DEFAULT
#  define ZSTD_CLEVEL_DEFAULT 3
#endif

#define ZSTD_MAGICNUMBER            0xFD2FB528        
#define ZSTD_MAGIC_DICTIONARY       0xEC30A437        
#define ZSTD_MAGIC_SKIPPABLE_START  0x184D2A50                   
#define ZSTD_MAGIC_SKIPPABLE_MASK   0xFFFFFFF0

#define ZSTD_BLOCKSIZELOG_MAX  17
#define ZSTD_BLOCKSIZE_MAX     (1<<ZSTD_BLOCKSIZELOG_MAX)



ZSTDLIB_API size_t ZSTD_compress( void* dst, size_t dstCapacity,
                            const void* src, size_t srcSize,
                                  int compressionLevel);

ZSTDLIB_API size_t ZSTD_decompress( void* dst, size_t dstCapacity,
                              const void* src, size_t compressedSize);

#define ZSTD_CONTENTSIZE_UNKNOWN (0ULL - 1)
#define ZSTD_CONTENTSIZE_ERROR   (0ULL - 2)
ZSTDLIB_API unsigned long long ZSTD_getFrameContentSize(const void *src, size_t srcSize);

ZSTDLIB_API unsigned long long ZSTD_getDecompressedSize(const void* src, size_t srcSize);

ZSTDLIB_API size_t ZSTD_findFrameCompressedSize(const void* src, size_t srcSize);


#define ZSTD_COMPRESSBOUND(srcSize)   ((srcSize) + ((srcSize)>>8) + (((srcSize) < (128<<10)) ? (((128<<10) - (srcSize)) >> 11)        : 0))                     
ZSTDLIB_API size_t      ZSTD_compressBound(size_t srcSize);          
ZSTDLIB_API unsigned    ZSTD_isError(size_t code);                     
ZSTDLIB_API const char* ZSTD_getErrorName(size_t code);             
ZSTDLIB_API int         ZSTD_minCLevel(void);                     
ZSTDLIB_API int         ZSTD_maxCLevel(void);                    


typedef struct ZSTD_CCtx_s ZSTD_CCtx;
ZSTDLIB_API ZSTD_CCtx* ZSTD_createCCtx(void);
ZSTDLIB_API size_t     ZSTD_freeCCtx(ZSTD_CCtx* cctx);

ZSTDLIB_API size_t ZSTD_compressCCtx(ZSTD_CCtx* cctx,
                                     void* dst, size_t dstCapacity,
                               const void* src, size_t srcSize,
                                     int compressionLevel);

typedef struct ZSTD_DCtx_s ZSTD_DCtx;
ZSTDLIB_API ZSTD_DCtx* ZSTD_createDCtx(void);
ZSTDLIB_API size_t     ZSTD_freeDCtx(ZSTD_DCtx* dctx);

ZSTDLIB_API size_t ZSTD_decompressDCtx(ZSTD_DCtx* dctx,
                                       void* dst, size_t dstCapacity,
                                 const void* src, size_t srcSize);



typedef enum { ZSTD_fast=1,
               ZSTD_dfast=2,
               ZSTD_greedy=3,
               ZSTD_lazy=4,
               ZSTD_lazy2=5,
               ZSTD_btlazy2=6,
               ZSTD_btopt=7,
               ZSTD_btultra=8,
               ZSTD_btultra2=9
} ZSTD_strategy;


typedef enum {

    ZSTD_c_compressionLevel=100,         
    ZSTD_c_windowLog=101,             
    ZSTD_c_hashLog=102,                 
    ZSTD_c_chainLog=103,                
    ZSTD_c_searchLog=104,             
    ZSTD_c_minMatch=105,          
    ZSTD_c_targetLength=106,        
    ZSTD_c_strategy=107,         
    ZSTD_c_enableLongDistanceMatching=160,     
    ZSTD_c_ldmHashLog=161,                
    ZSTD_c_ldmMinMatch=162,         
    ZSTD_c_ldmBucketSizeLog=163,              
    ZSTD_c_ldmHashRateLog=164,           
    ZSTD_c_contentSizeFlag=200,            
    ZSTD_c_checksumFlag=201,              
    ZSTD_c_dictIDFlag=202,              

    ZSTD_c_nbWorkers=400,               
    ZSTD_c_jobSize=401,                    
    ZSTD_c_overlapLog=402,             
     ZSTD_c_experimentalParam1=500,
     ZSTD_c_experimentalParam2=10,
     ZSTD_c_experimentalParam3=1000,
     ZSTD_c_experimentalParam4=1001,
     ZSTD_c_experimentalParam5=1002,
     ZSTD_c_experimentalParam6=1003,
     ZSTD_c_experimentalParam7=1004
} ZSTD_cParameter;

typedef struct {
    size_t error;
    int lowerBound;
    int upperBound;
} ZSTD_bounds;

ZSTDLIB_API ZSTD_bounds ZSTD_cParam_getBounds(ZSTD_cParameter cParam);

ZSTDLIB_API size_t ZSTD_CCtx_setParameter(ZSTD_CCtx* cctx, ZSTD_cParameter param, int value);

ZSTDLIB_API size_t ZSTD_CCtx_setPledgedSrcSize(ZSTD_CCtx* cctx, unsigned long long pledgedSrcSize);

typedef enum {
    ZSTD_reset_session_only = 1,
    ZSTD_reset_parameters = 2,
    ZSTD_reset_session_and_parameters = 3
} ZSTD_ResetDirective;

ZSTDLIB_API size_t ZSTD_CCtx_reset(ZSTD_CCtx* cctx, ZSTD_ResetDirective reset);

ZSTDLIB_API size_t ZSTD_compress2( ZSTD_CCtx* cctx,
                                   void* dst, size_t dstCapacity,
                             const void* src, size_t srcSize);


typedef enum {

    ZSTD_d_windowLogMax=100,           
     ZSTD_d_experimentalParam1=1000,
     ZSTD_d_experimentalParam2=1001

} ZSTD_dParameter;

ZSTDLIB_API ZSTD_bounds ZSTD_dParam_getBounds(ZSTD_dParameter dParam);

ZSTDLIB_API size_t ZSTD_DCtx_setParameter(ZSTD_DCtx* dctx, ZSTD_dParameter param, int value);

ZSTDLIB_API size_t ZSTD_DCtx_reset(ZSTD_DCtx* dctx, ZSTD_ResetDirective reset);


typedef struct ZSTD_inBuffer_s {
  const void* src;         
  size_t size;             
  size_t pos;                       
} ZSTD_inBuffer;

typedef struct ZSTD_outBuffer_s {
  void*  dst;              
  size_t size;             
  size_t pos;                       
} ZSTD_outBuffer;



typedef ZSTD_CCtx ZSTD_CStream;             
ZSTDLIB_API ZSTD_CStream* ZSTD_createCStream(void);
ZSTDLIB_API size_t ZSTD_freeCStream(ZSTD_CStream* zcs);

typedef enum {
    ZSTD_e_continue=0,                
    ZSTD_e_flush=1,          
    ZSTD_e_end=2               
} ZSTD_EndDirective;

ZSTDLIB_API size_t ZSTD_compressStream2( ZSTD_CCtx* cctx,
                                         ZSTD_outBuffer* output,
                                         ZSTD_inBuffer* input,
                                         ZSTD_EndDirective endOp);


ZSTDLIB_API size_t ZSTD_CStreamInSize(void);          
ZSTDLIB_API size_t ZSTD_CStreamOutSize(void);                   


ZSTDLIB_API size_t ZSTD_initCStream(ZSTD_CStream* zcs, int compressionLevel);
ZSTDLIB_API size_t ZSTD_compressStream(ZSTD_CStream* zcs, ZSTD_outBuffer* output, ZSTD_inBuffer* input);
ZSTDLIB_API size_t ZSTD_flushStream(ZSTD_CStream* zcs, ZSTD_outBuffer* output);
ZSTDLIB_API size_t ZSTD_endStream(ZSTD_CStream* zcs, ZSTD_outBuffer* output);


typedef ZSTD_DCtx ZSTD_DStream;             
ZSTDLIB_API ZSTD_DStream* ZSTD_createDStream(void);
ZSTDLIB_API size_t ZSTD_freeDStream(ZSTD_DStream* zds);

ZSTDLIB_API size_t ZSTD_initDStream(ZSTD_DStream* zds);

ZSTDLIB_API size_t ZSTD_decompressStream(ZSTD_DStream* zds, ZSTD_outBuffer* output, ZSTD_inBuffer* input);

ZSTDLIB_API size_t ZSTD_DStreamInSize(void);          
ZSTDLIB_API size_t ZSTD_DStreamOutSize(void);                     


ZSTDLIB_API size_t ZSTD_compress_usingDict(ZSTD_CCtx* ctx,
                                           void* dst, size_t dstCapacity,
                                     const void* src, size_t srcSize,
                                     const void* dict,size_t dictSize,
                                           int compressionLevel);

ZSTDLIB_API size_t ZSTD_decompress_usingDict(ZSTD_DCtx* dctx,
                                             void* dst, size_t dstCapacity,
                                       const void* src, size_t srcSize,
                                       const void* dict,size_t dictSize);


typedef struct ZSTD_CDict_s ZSTD_CDict;

ZSTDLIB_API ZSTD_CDict* ZSTD_createCDict(const void* dictBuffer, size_t dictSize,
                                         int compressionLevel);

ZSTDLIB_API size_t      ZSTD_freeCDict(ZSTD_CDict* CDict);

ZSTDLIB_API size_t ZSTD_compress_usingCDict(ZSTD_CCtx* cctx,
                                            void* dst, size_t dstCapacity,
                                      const void* src, size_t srcSize,
                                      const ZSTD_CDict* cdict);


typedef struct ZSTD_DDict_s ZSTD_DDict;

ZSTDLIB_API ZSTD_DDict* ZSTD_createDDict(const void* dictBuffer, size_t dictSize);

ZSTDLIB_API size_t      ZSTD_freeDDict(ZSTD_DDict* ddict);

ZSTDLIB_API size_t ZSTD_decompress_usingDDict(ZSTD_DCtx* dctx,
                                              void* dst, size_t dstCapacity,
                                        const void* src, size_t srcSize,
                                        const ZSTD_DDict* ddict);


ZSTDLIB_API unsigned ZSTD_getDictID_fromDict(const void* dict, size_t dictSize);

ZSTDLIB_API unsigned ZSTD_getDictID_fromDDict(const ZSTD_DDict* ddict);

ZSTDLIB_API unsigned ZSTD_getDictID_fromFrame(const void* src, size_t srcSize);



ZSTDLIB_API size_t ZSTD_CCtx_loadDictionary(ZSTD_CCtx* cctx, const void* dict, size_t dictSize);

ZSTDLIB_API size_t ZSTD_CCtx_refCDict(ZSTD_CCtx* cctx, const ZSTD_CDict* cdict);

ZSTDLIB_API size_t ZSTD_CCtx_refPrefix(ZSTD_CCtx* cctx,
                                 const void* prefix, size_t prefixSize);

ZSTDLIB_API size_t ZSTD_DCtx_loadDictionary(ZSTD_DCtx* dctx, const void* dict, size_t dictSize);

ZSTDLIB_API size_t ZSTD_DCtx_refDDict(ZSTD_DCtx* dctx, const ZSTD_DDict* ddict);

ZSTDLIB_API size_t ZSTD_DCtx_refPrefix(ZSTD_DCtx* dctx,
                                 const void* prefix, size_t prefixSize);

ZSTDLIB_API size_t ZSTD_sizeof_CCtx(const ZSTD_CCtx* cctx);
ZSTDLIB_API size_t ZSTD_sizeof_DCtx(const ZSTD_DCtx* dctx);
ZSTDLIB_API size_t ZSTD_sizeof_CStream(const ZSTD_CStream* zcs);
ZSTDLIB_API size_t ZSTD_sizeof_DStream(const ZSTD_DStream* zds);
ZSTDLIB_API size_t ZSTD_sizeof_CDict(const ZSTD_CDict* cdict);
ZSTDLIB_API size_t ZSTD_sizeof_DDict(const ZSTD_DDict* ddict);

#endif    


#if defined(ZSTD_STATIC_LINKING_ONLY) && !defined(ZSTD_H_ZSTD_STATIC_LINKING_ONLY)
#define ZSTD_H_ZSTD_STATIC_LINKING_ONLY

#define ZSTD_FRAMEHEADERSIZE_PREFIX(format) ((format) == ZSTD_f_zstd1 ? 5 : 1)             
#define ZSTD_FRAMEHEADERSIZE_MIN(format)    ((format) == ZSTD_f_zstd1 ? 6 : 2)
#define ZSTD_FRAMEHEADERSIZE_MAX   18          
#define ZSTD_SKIPPABLEHEADERSIZE    8

#define ZSTD_WINDOWLOG_MAX_32    30
#define ZSTD_WINDOWLOG_MAX_64    31
#define ZSTD_WINDOWLOG_MAX     ((int)(sizeof(size_t) == 4 ? ZSTD_WINDOWLOG_MAX_32 : ZSTD_WINDOWLOG_MAX_64))
#define ZSTD_WINDOWLOG_MIN       10
#define ZSTD_HASHLOG_MAX       ((ZSTD_WINDOWLOG_MAX < 30) ? ZSTD_WINDOWLOG_MAX : 30)
#define ZSTD_HASHLOG_MIN          6
#define ZSTD_CHAINLOG_MAX_32     29
#define ZSTD_CHAINLOG_MAX_64     30
#define ZSTD_CHAINLOG_MAX      ((int)(sizeof(size_t) == 4 ? ZSTD_CHAINLOG_MAX_32 : ZSTD_CHAINLOG_MAX_64))
#define ZSTD_CHAINLOG_MIN        ZSTD_HASHLOG_MIN
#define ZSTD_SEARCHLOG_MAX      (ZSTD_WINDOWLOG_MAX-1)
#define ZSTD_SEARCHLOG_MIN        1
#define ZSTD_MINMATCH_MAX         7             
#define ZSTD_MINMATCH_MIN         3             
#define ZSTD_TARGETLENGTH_MAX    ZSTD_BLOCKSIZE_MAX
#define ZSTD_TARGETLENGTH_MIN     0                 
#define ZSTD_STRATEGY_MIN        ZSTD_fast
#define ZSTD_STRATEGY_MAX        ZSTD_btultra2


#define ZSTD_OVERLAPLOG_MIN       0
#define ZSTD_OVERLAPLOG_MAX       9

#define ZSTD_WINDOWLOG_LIMIT_DEFAULT 27            

#define ZSTD_LDM_HASHLOG_MIN      ZSTD_HASHLOG_MIN
#define ZSTD_LDM_HASHLOG_MAX      ZSTD_HASHLOG_MAX
#define ZSTD_LDM_MINMATCH_MIN        4
#define ZSTD_LDM_MINMATCH_MAX     4096
#define ZSTD_LDM_BUCKETSIZELOG_MIN   1
#define ZSTD_LDM_BUCKETSIZELOG_MAX   8
#define ZSTD_LDM_HASHRATELOG_MIN     0
#define ZSTD_LDM_HASHRATELOG_MAX (ZSTD_WINDOWLOG_MAX - ZSTD_HASHLOG_MIN)

#define ZSTD_TARGETCBLOCKSIZE_MIN   64
#define ZSTD_TARGETCBLOCKSIZE_MAX   ZSTD_BLOCKSIZE_MAX
#define ZSTD_SRCSIZEHINT_MIN        0
#define ZSTD_SRCSIZEHINT_MAX        INT_MAX

#define ZSTD_HASHLOG3_MAX           17


typedef struct ZSTD_CCtx_params_s ZSTD_CCtx_params;

typedef struct {
    unsigned int matchPos;      
    unsigned int offset;
    unsigned int litLength;    
    unsigned int matchLength;    
    unsigned int rep;
} ZSTD_Sequence;

typedef struct {
    unsigned windowLog;                     
    unsigned chainLog;                       
    unsigned hashLog;                  
    unsigned searchLog;                 
    unsigned minMatch;                    
    unsigned targetLength;                  
    ZSTD_strategy strategy;        
} ZSTD_compressionParameters;

typedef struct {
    int contentSizeFlag;            
    int checksumFlag;                    
    int noDictIDFlag;                     
} ZSTD_frameParameters;

typedef struct {
    ZSTD_compressionParameters cParams;
    ZSTD_frameParameters fParams;
} ZSTD_parameters;

typedef enum {
    ZSTD_dct_auto = 0,                   
    ZSTD_dct_rawContent = 1,               
    ZSTD_dct_fullDict = 2                    
} ZSTD_dictContentType_e;

typedef enum {
    ZSTD_dlm_byCopy = 0,       
    ZSTD_dlm_byRef = 1                
} ZSTD_dictLoadMethod_e;

typedef enum {
    ZSTD_f_zstd1 = 0,                   
    ZSTD_f_zstd1_magicless = 1            
} ZSTD_format_e;

typedef enum {
    ZSTD_dictDefaultAttach = 0,      
    ZSTD_dictForceAttach   = 1,      
    ZSTD_dictForceCopy     = 2,      
    ZSTD_dictForceLoad     = 3       
} ZSTD_dictAttachPref_e;

typedef enum {
  ZSTD_lcm_auto = 0,                    
  ZSTD_lcm_huffman = 1,                
  ZSTD_lcm_uncompressed = 2        
} ZSTD_literalCompressionMode_e;


ZSTDLIB_API unsigned long long ZSTD_findDecompressedSize(const void* src, size_t srcSize);

ZSTDLIB_API unsigned long long ZSTD_decompressBound(const void* src, size_t srcSize);

ZSTDLIB_API size_t ZSTD_frameHeaderSize(const void* src, size_t srcSize);

ZSTDLIB_API size_t ZSTD_getSequences(ZSTD_CCtx* zc, ZSTD_Sequence* outSeqs,
    size_t outSeqsSize, const void* src, size_t srcSize);


ZSTDLIB_API size_t ZSTD_estimateCCtxSize(int compressionLevel);
ZSTDLIB_API size_t ZSTD_estimateCCtxSize_usingCParams(ZSTD_compressionParameters cParams);
ZSTDLIB_API size_t ZSTD_estimateCCtxSize_usingCCtxParams(const ZSTD_CCtx_params* params);
ZSTDLIB_API size_t ZSTD_estimateDCtxSize(void);

ZSTDLIB_API size_t ZSTD_estimateCStreamSize(int compressionLevel);
ZSTDLIB_API size_t ZSTD_estimateCStreamSize_usingCParams(ZSTD_compressionParameters cParams);
ZSTDLIB_API size_t ZSTD_estimateCStreamSize_usingCCtxParams(const ZSTD_CCtx_params* params);
ZSTDLIB_API size_t ZSTD_estimateDStreamSize(size_t windowSize);
ZSTDLIB_API size_t ZSTD_estimateDStreamSize_fromFrame(const void* src, size_t srcSize);

ZSTDLIB_API size_t ZSTD_estimateCDictSize(size_t dictSize, int compressionLevel);
ZSTDLIB_API size_t ZSTD_estimateCDictSize_advanced(size_t dictSize, ZSTD_compressionParameters cParams, ZSTD_dictLoadMethod_e dictLoadMethod);
ZSTDLIB_API size_t ZSTD_estimateDDictSize(size_t dictSize, ZSTD_dictLoadMethod_e dictLoadMethod);

ZSTDLIB_API ZSTD_CCtx*    ZSTD_initStaticCCtx(void* workspace, size_t workspaceSize);
ZSTDLIB_API ZSTD_CStream* ZSTD_initStaticCStream(void* workspace, size_t workspaceSize);        

ZSTDLIB_API ZSTD_DCtx*    ZSTD_initStaticDCtx(void* workspace, size_t workspaceSize);
ZSTDLIB_API ZSTD_DStream* ZSTD_initStaticDStream(void* workspace, size_t workspaceSize);        

ZSTDLIB_API const ZSTD_CDict* ZSTD_initStaticCDict(
                                        void* workspace, size_t workspaceSize,
                                        const void* dict, size_t dictSize,
                                        ZSTD_dictLoadMethod_e dictLoadMethod,
                                        ZSTD_dictContentType_e dictContentType,
                                        ZSTD_compressionParameters cParams);

ZSTDLIB_API const ZSTD_DDict* ZSTD_initStaticDDict(
                                        void* workspace, size_t workspaceSize,
                                        const void* dict, size_t dictSize,
                                        ZSTD_dictLoadMethod_e dictLoadMethod,
                                        ZSTD_dictContentType_e dictContentType);


typedef void* (*ZSTD_allocFunction) (void* opaque, size_t size);
typedef void  (*ZSTD_freeFunction) (void* opaque, void* address);
typedef struct { ZSTD_allocFunction customAlloc; ZSTD_freeFunction customFree; void* opaque; } ZSTD_customMem;
static ZSTD_customMem const ZSTD_defaultCMem = { NULL, NULL, NULL };         

ZSTDLIB_API ZSTD_CCtx*    ZSTD_createCCtx_advanced(ZSTD_customMem customMem);
ZSTDLIB_API ZSTD_CStream* ZSTD_createCStream_advanced(ZSTD_customMem customMem);
ZSTDLIB_API ZSTD_DCtx*    ZSTD_createDCtx_advanced(ZSTD_customMem customMem);
ZSTDLIB_API ZSTD_DStream* ZSTD_createDStream_advanced(ZSTD_customMem customMem);

ZSTDLIB_API ZSTD_CDict* ZSTD_createCDict_advanced(const void* dict, size_t dictSize,
                                                  ZSTD_dictLoadMethod_e dictLoadMethod,
                                                  ZSTD_dictContentType_e dictContentType,
                                                  ZSTD_compressionParameters cParams,
                                                  ZSTD_customMem customMem);

ZSTDLIB_API ZSTD_DDict* ZSTD_createDDict_advanced(const void* dict, size_t dictSize,
                                                  ZSTD_dictLoadMethod_e dictLoadMethod,
                                                  ZSTD_dictContentType_e dictContentType,
                                                  ZSTD_customMem customMem);



ZSTDLIB_API ZSTD_CDict* ZSTD_createCDict_byReference(const void* dictBuffer, size_t dictSize, int compressionLevel);

ZSTDLIB_API ZSTD_compressionParameters ZSTD_getCParams(int compressionLevel, unsigned long long estimatedSrcSize, size_t dictSize);

ZSTDLIB_API ZSTD_parameters ZSTD_getParams(int compressionLevel, unsigned long long estimatedSrcSize, size_t dictSize);

ZSTDLIB_API size_t ZSTD_checkCParams(ZSTD_compressionParameters params);

ZSTDLIB_API ZSTD_compressionParameters ZSTD_adjustCParams(ZSTD_compressionParameters cPar, unsigned long long srcSize, size_t dictSize);

ZSTDLIB_API size_t ZSTD_compress_advanced(ZSTD_CCtx* cctx,
                                          void* dst, size_t dstCapacity,
                                    const void* src, size_t srcSize,
                                    const void* dict,size_t dictSize,
                                          ZSTD_parameters params);

ZSTDLIB_API size_t ZSTD_compress_usingCDict_advanced(ZSTD_CCtx* cctx,
                                              void* dst, size_t dstCapacity,
                                        const void* src, size_t srcSize,
                                        const ZSTD_CDict* cdict,
                                              ZSTD_frameParameters fParams);


ZSTDLIB_API size_t ZSTD_CCtx_loadDictionary_byReference(ZSTD_CCtx* cctx, const void* dict, size_t dictSize);

ZSTDLIB_API size_t ZSTD_CCtx_loadDictionary_advanced(ZSTD_CCtx* cctx, const void* dict, size_t dictSize, ZSTD_dictLoadMethod_e dictLoadMethod, ZSTD_dictContentType_e dictContentType);

ZSTDLIB_API size_t ZSTD_CCtx_refPrefix_advanced(ZSTD_CCtx* cctx, const void* prefix, size_t prefixSize, ZSTD_dictContentType_e dictContentType);

 #define ZSTD_c_rsyncable ZSTD_c_experimentalParam1

#define ZSTD_c_format ZSTD_c_experimentalParam2

#define ZSTD_c_forceMaxWindow ZSTD_c_experimentalParam3

#define ZSTD_c_forceAttachDict ZSTD_c_experimentalParam4

#define ZSTD_c_literalCompressionMode ZSTD_c_experimentalParam5

#define ZSTD_c_targetCBlockSize ZSTD_c_experimentalParam6

#define ZSTD_c_srcSizeHint ZSTD_c_experimentalParam7

ZSTDLIB_API size_t ZSTD_CCtx_getParameter(ZSTD_CCtx* cctx, ZSTD_cParameter param, int* value);


ZSTDLIB_API ZSTD_CCtx_params* ZSTD_createCCtxParams(void);
ZSTDLIB_API size_t ZSTD_freeCCtxParams(ZSTD_CCtx_params* params);

ZSTDLIB_API size_t ZSTD_CCtxParams_reset(ZSTD_CCtx_params* params);

ZSTDLIB_API size_t ZSTD_CCtxParams_init(ZSTD_CCtx_params* cctxParams, int compressionLevel);

ZSTDLIB_API size_t ZSTD_CCtxParams_init_advanced(ZSTD_CCtx_params* cctxParams, ZSTD_parameters params);

ZSTDLIB_API size_t ZSTD_CCtxParams_setParameter(ZSTD_CCtx_params* params, ZSTD_cParameter param, int value);

ZSTDLIB_API size_t ZSTD_CCtxParams_getParameter(ZSTD_CCtx_params* params, ZSTD_cParameter param, int* value);

ZSTDLIB_API size_t ZSTD_CCtx_setParametersUsingCCtxParams(
        ZSTD_CCtx* cctx, const ZSTD_CCtx_params* params);

ZSTDLIB_API size_t ZSTD_compressStream2_simpleArgs (
                            ZSTD_CCtx* cctx,
                            void* dst, size_t dstCapacity, size_t* dstPos,
                      const void* src, size_t srcSize, size_t* srcPos,
                            ZSTD_EndDirective endOp);


ZSTDLIB_API unsigned ZSTD_isFrame(const void* buffer, size_t size);

ZSTDLIB_API ZSTD_DDict* ZSTD_createDDict_byReference(const void* dictBuffer, size_t dictSize);

ZSTDLIB_API size_t ZSTD_DCtx_loadDictionary_byReference(ZSTD_DCtx* dctx, const void* dict, size_t dictSize);

ZSTDLIB_API size_t ZSTD_DCtx_loadDictionary_advanced(ZSTD_DCtx* dctx, const void* dict, size_t dictSize, ZSTD_dictLoadMethod_e dictLoadMethod, ZSTD_dictContentType_e dictContentType);

ZSTDLIB_API size_t ZSTD_DCtx_refPrefix_advanced(ZSTD_DCtx* dctx, const void* prefix, size_t prefixSize, ZSTD_dictContentType_e dictContentType);

ZSTDLIB_API size_t ZSTD_DCtx_setMaxWindowSize(ZSTD_DCtx* dctx, size_t maxWindowSize);

#define ZSTD_d_format ZSTD_d_experimentalParam1
#define ZSTD_d_stableOutBuffer ZSTD_d_experimentalParam2

ZSTDLIB_API size_t ZSTD_DCtx_setFormat(ZSTD_DCtx* dctx, ZSTD_format_e format);

ZSTDLIB_API size_t ZSTD_decompressStream_simpleArgs (
                            ZSTD_DCtx* dctx,
                            void* dst, size_t dstCapacity, size_t* dstPos,
                      const void* src, size_t srcSize, size_t* srcPos);


ZSTDLIB_API size_t
ZSTD_initCStream_srcSize(ZSTD_CStream* zcs,
                         int compressionLevel,
                         unsigned long long pledgedSrcSize);

ZSTDLIB_API size_t
ZSTD_initCStream_usingDict(ZSTD_CStream* zcs,
                     const void* dict, size_t dictSize,
                           int compressionLevel);

ZSTDLIB_API size_t
ZSTD_initCStream_advanced(ZSTD_CStream* zcs,
                    const void* dict, size_t dictSize,
                          ZSTD_parameters params,
                          unsigned long long pledgedSrcSize);

ZSTDLIB_API size_t ZSTD_initCStream_usingCDict(ZSTD_CStream* zcs, const ZSTD_CDict* cdict);

ZSTDLIB_API size_t
ZSTD_initCStream_usingCDict_advanced(ZSTD_CStream* zcs,
                               const ZSTD_CDict* cdict,
                                     ZSTD_frameParameters fParams,
                                     unsigned long long pledgedSrcSize);

ZSTDLIB_API size_t ZSTD_resetCStream(ZSTD_CStream* zcs, unsigned long long pledgedSrcSize);


typedef struct {
    unsigned long long ingested;          
    unsigned long long consumed;         
    unsigned long long produced;           
    unsigned long long flushed;                   
    unsigned currentJobID;                 
    unsigned nbActiveWorkers;                  
} ZSTD_frameProgression;

ZSTDLIB_API ZSTD_frameProgression ZSTD_getFrameProgression(const ZSTD_CCtx* cctx);

ZSTDLIB_API size_t ZSTD_toFlushNow(ZSTD_CCtx* cctx);


ZSTDLIB_API size_t ZSTD_initDStream_usingDict(ZSTD_DStream* zds, const void* dict, size_t dictSize);

ZSTDLIB_API size_t ZSTD_initDStream_usingDDict(ZSTD_DStream* zds, const ZSTD_DDict* ddict);

ZSTDLIB_API size_t ZSTD_resetDStream(ZSTD_DStream* zds);


ZSTDLIB_API size_t ZSTD_compressBegin(ZSTD_CCtx* cctx, int compressionLevel);
ZSTDLIB_API size_t ZSTD_compressBegin_usingDict(ZSTD_CCtx* cctx, const void* dict, size_t dictSize, int compressionLevel);
ZSTDLIB_API size_t ZSTD_compressBegin_advanced(ZSTD_CCtx* cctx, const void* dict, size_t dictSize, ZSTD_parameters params, unsigned long long pledgedSrcSize);              
ZSTDLIB_API size_t ZSTD_compressBegin_usingCDict(ZSTD_CCtx* cctx, const ZSTD_CDict* cdict);      
ZSTDLIB_API size_t ZSTD_compressBegin_usingCDict_advanced(ZSTD_CCtx* const cctx, const ZSTD_CDict* const cdict, ZSTD_frameParameters const fParams, unsigned long long const pledgedSrcSize);                       
ZSTDLIB_API size_t ZSTD_copyCCtx(ZSTD_CCtx* cctx, const ZSTD_CCtx* preparedCCtx, unsigned long long pledgedSrcSize);           

ZSTDLIB_API size_t ZSTD_compressContinue(ZSTD_CCtx* cctx, void* dst, size_t dstCapacity, const void* src, size_t srcSize);
ZSTDLIB_API size_t ZSTD_compressEnd(ZSTD_CCtx* cctx, void* dst, size_t dstCapacity, const void* src, size_t srcSize);


typedef enum { ZSTD_frame, ZSTD_skippableFrame } ZSTD_frameType_e;
typedef struct {
    unsigned long long frameContentSize;               
    unsigned long long windowSize;                
    unsigned blockSizeMax;
    ZSTD_frameType_e frameType;                     
    unsigned headerSize;
    unsigned dictID;
    unsigned checksumFlag;
} ZSTD_frameHeader;

ZSTDLIB_API size_t ZSTD_getFrameHeader(ZSTD_frameHeader* zfhPtr, const void* src, size_t srcSize);       
ZSTDLIB_API size_t ZSTD_getFrameHeader_advanced(ZSTD_frameHeader* zfhPtr, const void* src, size_t srcSize, ZSTD_format_e format);
ZSTDLIB_API size_t ZSTD_decodingBufferSize_min(unsigned long long windowSize, unsigned long long frameContentSize);               

ZSTDLIB_API size_t ZSTD_decompressBegin(ZSTD_DCtx* dctx);
ZSTDLIB_API size_t ZSTD_decompressBegin_usingDict(ZSTD_DCtx* dctx, const void* dict, size_t dictSize);
ZSTDLIB_API size_t ZSTD_decompressBegin_usingDDict(ZSTD_DCtx* dctx, const ZSTD_DDict* ddict);

ZSTDLIB_API size_t ZSTD_nextSrcSizeToDecompress(ZSTD_DCtx* dctx);
ZSTDLIB_API size_t ZSTD_decompressContinue(ZSTD_DCtx* dctx, void* dst, size_t dstCapacity, const void* src, size_t srcSize);

ZSTDLIB_API void   ZSTD_copyDCtx(ZSTD_DCtx* dctx, const ZSTD_DCtx* preparedDCtx);
typedef enum { ZSTDnit_frameHeader, ZSTDnit_blockHeader, ZSTDnit_block, ZSTDnit_lastBlock, ZSTDnit_checksum, ZSTDnit_skippableFrame } ZSTD_nextInputType_e;
ZSTDLIB_API ZSTD_nextInputType_e ZSTD_nextInputType(ZSTD_DCtx* dctx);




ZSTDLIB_API size_t ZSTD_getBlockSize   (const ZSTD_CCtx* cctx);
ZSTDLIB_API size_t ZSTD_compressBlock  (ZSTD_CCtx* cctx, void* dst, size_t dstCapacity, const void* src, size_t srcSize);
ZSTDLIB_API size_t ZSTD_decompressBlock(ZSTD_DCtx* dctx, void* dst, size_t dstCapacity, const void* src, size_t srcSize);
ZSTDLIB_API size_t ZSTD_insertBlock    (ZSTD_DCtx* dctx, const void* blockStart, size_t blockSize);             


#endif     

#if defined (__cplusplus)
}
#endif
