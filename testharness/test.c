/* ====================================================================
 * Copyright (c) 2015 IEEE.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the IEEE Industry
 *    Connections Security Group (ICSG)".
 *
 * 4. The name "IEEE" must not be used to endorse or promote products
 *    derived from this software without prior written permission from
 *    the IEEE Standards Association (stds.ipr@ieee.org).
 *
 * 5. Products derived from this software may not contain "IEEE" in
 *    their names without prior written permission from the IEEE Standards
 *    Association (stds.ipr@ieee.org).
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the IEEE Industry
 *    Connections Security Group (ICSG)".
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND "WITH ALL FAULTS." IEEE AND ITS
 * CONTRIBUTORS EXPRESSLY DISCLAIM ALL WARRANTIES AND REPRESENTATIONS,
 * EXPRESS OR IMPLIED, INCLUDING, WITHOUT LIMITATION:  (A) THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE;
 * (B) ANY WARRANTY OF NON-INFRINGEMENT; AND (C) ANY WARRANTY WITH RESPECT
 * TO THE QUALITY, ACCURACY, EFFECTIVENESS, CURRENCY OR COMPLETENESS OF
 * THE SOFTWARE.
 *
 * IN NO EVENT SHALL IEEE OR ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL,  EXEMPLARY, OR CONSEQUENTIAL DAMAGES,
 * (INCLUDING, BUT NOT LIMITED TO,  PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE AND REGARDLESS OF WHETHER SUCH DAMAGE WAS
 * FORESEEABLE.
 *
 * THIS SOFTWARE USES STRONG CRYPTOGRAPHY, WHICH MAY BE SUBJECT TO LAWS
 * AND REGULATIONS GOVERNING ITS USE, EXPORTATION OR IMPORTATION. YOU ARE
 * SOLELY RESPONSIBLE FOR COMPLYING WITH ALL APPLICABLE LAWS AND
 * REGULATIONS, INCLUDING, BUT NOT LIMITED TO, ANY THAT GOVERN YOUR USE,
 * EXPORTATION OR IMPORTATION OF THIS SOFTWARE. IEEE AND ITS CONTRIBUTORS
 * DISCLAIM ALL LIABILITY ARISING FROM YOUR USE OF THE SOFTWARE IN
 * VIOLATION OF ANY APPLICABLE LAWS OR REGULATIONS.
 * ====================================================================
 *
 * author: Peter Ferrie (peferrie@microsoft.com)
 */

#define __STDC_WANT_LIB_EXT1__ 1 
#include <io.h>
#include <malloc.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "pe_util.h"
#include "file_util.h"
#include "lib_util.h"
#include "spv_util.h"
#include "ssv_util.h"
#include "err.h"
#include "test.h"
#include "taggantlib.h"

//#define CSA_MODE
//#define SKIP_CREATE
//#define KEEP_FILES

#ifdef _WIN32
    /* avoid #include <windows.h> */

    #define HMODULE void*

    typedef int (__stdcall *FARPROC)();

    __declspec(dllimport) FARPROC __stdcall GetProcAddress(_In_ HMODULE hModule, _In_ const char* lpProcName);

    __declspec(dllimport) HMODULE __stdcall LoadLibraryA(_In_ const char* lpLibFileName);

    __declspec(dllimport) int __stdcall FreeLibrary(_In_ HMODULE hLibModule);
#else
    /* todo: */
#endif

#define PR_WIDTH "%-140s"

UNSIGNED32 (STDCALL *pTaggantInitializeLibrary) (_In_opt_ TAGGANTFUNCTIONS *pFuncs, _Out_writes_(1) UNSIGNED64 *puVersion);
UNSIGNED32 (STDCALL *pTaggantContextNewEx) (_Outptr_ PTAGGANTCONTEXT *pTaggantCtx);
UNSIGNED32 (STDCALL *pTaggantObjectNewEx) (_In_opt_ PTAGGANT pTaggant, UNSIGNED64 uVersion, TAGGANTCONTAINER eTaggantType, _Outptr_ PTAGGANTOBJ *pTaggantObj);
PPACKERINFO (STDCALL *pTaggantPackerInfo) (_In_ PTAGGANTOBJ pTaggantObj);
UNSIGNED32 (STDCALL *pTaggantGetLicenseExpirationDate) (_In_ const PVOID pLicense, _Out_writes_(1) UNSIGNED64 *pTime);
UNSIGNED32 (STDCALL *pTaggantAddHashRegion) (_Inout_ PTAGGANTOBJ pTaggantObj, UNSIGNED64 uOffset, UNSIGNED64 uLength);
UNSIGNED32 (STDCALL *pTaggantComputeHashes) (_Inout_ PTAGGANTCONTEXT pCtx, _Inout_ PTAGGANTOBJ pTaggantObj, _In_ PFILEOBJECT hFile, UNSIGNED64 uObjectEnd, UNSIGNED64 uFileEnd, UNSIGNED32 uTaggantSize);
UNSIGNED32 (STDCALL *pTaggantPutInfo) (_Inout_ PTAGGANTOBJ pTaggantObj, ENUMTAGINFO eKey, UNSIGNED16 Size, _In_reads_(Size) PINFO pInfo);
UNSIGNED32 (STDCALL *pTaggantPutTimestamp) (_Inout_ PTAGGANTOBJ pTaggantObj, _In_z_ const char* pTSUrl, UNSIGNED32 uTimeout);
UNSIGNED32 (STDCALL *pTaggantPrepare) (_Inout_ PTAGGANTOBJ pTaggantObj, _In_ const PVOID pLicense, _Out_writes_bytes_(*uTaggantReservedSize) PVOID pTaggantOut, _Inout_updates_(1) UNSIGNED32 *uTaggantReservedSize);
UNSIGNED32 (STDCALL *pTaggantCheckCertificate) (_In_ const PVOID pCert);
UNSIGNED32 (STDCALL *pTaggantGetTaggant) (_In_ PTAGGANTCONTEXT pCtx, _In_ PFILEOBJECT hFile, TAGGANTCONTAINER eContainer, _Inout_ PTAGGANT *pTaggant);
UNSIGNED32 (STDCALL *pTaggantValidateSignature) (_In_ PTAGGANTOBJ pTaggantObj, _In_ PTAGGANT pTaggant, _In_ const PVOID pRootCert);
UNSIGNED32 (STDCALL *pTaggantGetTimestamp) (_In_ PTAGGANTOBJ pTaggantObj, _Out_writes_(1) UNSIGNED64 *pTime, _In_ const PVOID pTSRootCert);
UNSIGNED16 (STDCALL *pTaggantGetHashMapDoubles) (_In_ PTAGGANTOBJ pTaggantObj, _Out_writes_(1) PHASHBLOB_HASHMAP_DOUBLE *pDoubles);
UNSIGNED32 (STDCALL *pTaggantValidateHashMap) (_In_ PTAGGANTCONTEXT pCtx, _In_ PTAGGANTOBJ pTaggantObj, _In_ PFILEOBJECT hFile);
UNSIGNED32 (STDCALL *pTaggantGetInfo) (_In_ PTAGGANTOBJ pTaggantObj, ENUMTAGINFO eKey, _Inout_updates_(1) UNSIGNED32 *pSize, _Out_writes_opt_(*pSize) PINFO pInfo);
UNSIGNED32 (STDCALL *pTaggantValidateDefaultHashes) (_In_ PTAGGANTCONTEXT pCtx, _In_ PTAGGANTOBJ pTaggantObj, _In_ PFILEOBJECT hFile, UNSIGNED64 uObjectEnd, UNSIGNED64 uFileEnd);
UNSIGNED32 (STDCALL *pTaggantFreeTaggant) (_Post_ptr_invalid_ PTAGGANT pTaggant);
void (STDCALL *pTaggantContextFree) (_Post_ptr_invalid_ PTAGGANTCONTEXT pTaggantCtx);
void (STDCALL *pTaggantObjectFree) (_Post_ptr_invalid_ PTAGGANTOBJ pTaggantObj);
void (STDCALL *pTaggantFinalizeLibrary) (void);

#if !defined(FALSE)
#define FALSE 0
#endif
#if !defined(TRUE)
#define TRUE 1
#endif

enum
{
    LVL_UNKNOWN,
    LVL_MSGONLY,
    LVL_CLOSEDATA,
    LVL_FREELIC,
    LVL_FREEROOT = LVL_FREELIC,
    LVL_FREEPE32,
    LVL_FREEPE64,
    LVL_FREEJS,
    LVL_FREEDLL,
    LVL_FINALISE,
};

enum
{
    MODE_SPV,
    MODE_SSV
};

static void print_tagerr(int err)
{
    switch (err)
    {
        case TTYPE:
        {
            printf("the library does not support the requested version or TaggantType\n");
            break;
        }

        case TNOTAGGANTS:
        {
            printf("the file does not contain a Taggant\n");
            break;
        }

        case TMEMORY:
        case ERR_NOMEM:
        {
            printf("there is not enough memory to allocate the structure\n");
            break;
        }

        case TFILEERROR:
        {
            printf("object size is larger than the file size\n");
            break;
        }

        case TBADKEY:
        {
            printf("CMS validation has failed\n");
            break;
        }

        case TMISMATCH:
        {
            printf("hashes do not match\n");
            break;
        }

        case TERRORKEY:
        {
            printf("the type of information passed by the ENUMTAGINFO parameter is not supported\n");
            break;
        }

        case TNONET:
        {
            printf("no connection to the internet\n");
            break;
        }

        case TTIMEOUT:
        {
            printf("the timestamp authority server response time has expired\n");
            break;
        }

        case TINTERNALERROR:
        {
            printf("unspecified error during timestamp operation\n");
            break;
        }

        case TSERVERERROR:
        {
            printf("the timestamp authority server returned an error\n");
            break;
        }

        case TERROR:
        {
            printf("TAGGANTOBJ does not contain the TAGGANTBLOB structure\n");
            break;
        }

        case TNOTIME:
        {
            printf("the Taggant does not contain the time of the file's signature\n");
            break;
        }

        case TINVALID:
        {
            printf("the response from the Timestamp Authority server is incorrect\n");
            break;
        }

        case TLIBNOTINIT:
        {
            printf("the Taggant library has not been initialized using the TaggantLibraryInitialize function.\n");
            break;
        }

        case TINVALIDPEFILE:
        case ERR_BADPE:
        {
            printf("PE file is malformed\n");
            break;
        }

        case TINVALIDPEENTRYPOINT:
        {
            printf("the entry point of the PE file is not found\n");
            break;
        }

        case TINVALIDTAGGANTOFFSET:
        {
            printf("the Taggant structure is incorrect\n");
            break;
        }

        case TINVALIDTAGGANT:
        {
            printf("the Taggant structure is damaged\n");
            break;
        }

        case TFILEACCESSDENIED:
        case ERR_BADREAD:
        {
            printf("operations with the file returned an error\n");
            break;
        }

        case TENTRIESEXCEED:
        {
            printf("number of regions exceeded the maximum allowed\n");
            break;
        }

        case TINSUFFICIENTBUFFER:
        {
            printf("buffer for data is to small to hold the data\n");
            break;
        }

        case TNOTIMPLEMENTED:
        {
            printf("the required functionality is not implemented\n");
            break;
        }

        case TNOTFOUND:
        {
            printf("the requested tag does not exist\n");
            break;
        }

        case TINVALIDJSONFILE:
        {
            printf("invalid JSON file\n");
            break;
        }

        case ERR_BADOPEN:
        {
            printf("error opening a file\n");
            break;
        }

        case ERR_BADFILE:
        {
            printf("file seek or read failure\n");
            break;
        }

        case ERR_BADLIB:
        {
            printf("error resolving function or unsupported behaviour\n");
            break;
        }

        case ERR_BADLIBVER:
        {
            printf("library does not support requested version\n");
            break;
        }

        default:
        {
            printf("error: unsupported error number %d\n",
                   err
                  );
        }
    }
}

#if !defined(KEEP_FILES)
static const char *spv_files[] =
{
    "v1test01",    "v1test02",       "v1test03",       "v1test04",       "v1test05",       "v1test06",       "v1test07",    "v1test08",
    "v1test09",    "v1test10",       "v1test11",       "v1test12",       "v1tampered1_32", "v1test13",       "v1test14",    "v1tampered1_64",
    "v1test15",    "v1test16",       "v1test17",       "v1tampered2_32", "v1test18",       "v1tampered2_64", "v1test19",    "v1test20",
    "v1test21",    "v1test22",       "v1badhmh_32",    "v1test23",       "v2badhmh_32",    "v1test24",       "v1badhmh_64", "v1test25",
    "v2badhmh_64", "v1test26",       "v1test27",       "v1test28",       "v1test29",       "v1test30",       "v1test31",    "v1test32",
    "v2test01",    "v2test02",       "v2test03",       "v2test04",       "v2test05",       "v2test06",       "v2test07",    "v2test08",
    "v2test09",    "v2test10",       "v2test11",       "v2test12",       "v2test13",       "v2test14",       "v2test15",    "v2test16",
    "v2test17",    "v2tampered1_32", "v2test18",       "v2test19",       "v2tampered1_64", "v2test20",       "v2test21",    "v2tampered2_32",
    "v2test22",    "v2test23",       "v2tampered2_64", "v2test24",       "v2test25",       "v2test26",       "v2test27",    "v2test28",
    "v2test29",    "v2test30",       "v2test31",       "v2test32",       "v2test33",       "v2test34",       "v2test35",    "v2test36",
    "v2test37",    "v2test38",       "v2test39",       "v2test40",       "v2test41",       "v2test42",       "v2test43",    "v2test44",
    "v2test45",    "v2test46",       "v2test47",       "v2test48",       "v2test49",       "v2test50",       "v2test51",    "v2test52",
    "v2test55",    "v2test56",       "v2test57",       "v2test58",       "v2test59",       "v2test60",       "v2test61",    "v2test62",
    "v2test63",    "v2test64",       "v2test65",       "vdstest01",      "vdstest02",      "vdstest03",      "vdstest04",   "vdstest05",
    "vdstest06",   "vdstest07",      "vdstest08",      "vdstest09",      "vdstest10",      "veoftest01",     "veoftest02",  "v3test01",
    "v3test02",    "v3test03"
};

static void delete_spv(void)
{
    int i;

    i = 0;

    do
    {
        _unlink(spv_files[i]);
    }
    while (++i < (sizeof(spv_files) / sizeof(char *)));
}

static const char *ssv_files[] =
{
    "vssvtest001", "vssvtest007", "vssvtest023", "vssvtest024", "vssvtest025", "vssvtest026", "vssvtest027", "vssvtest028",
    "vssvtest029", "vssvtest030", "vssvtest031", "vssvtest032", "vssvtest035", "vssvtest036", "vssvtest037", "vssvtest040",
    "vssvtest041", "vssvtest042", "vssvtest047", "vssvtest048", "vssvtest049", "vssvtest050", "vssvtest051", "vssvtest052",
    "vssvtest053", "vssvtest054", "vssvtest055", "vssvtest056", "vssvtest059", "vssvtest060", "vssvtest061", "vssvtest062",
    "vssvtest063", "vssvtest064", "vssvtest065", "vssvtest066", "vssvtest067", "vssvtest068", "vssvtest115", "vssvtest116",
    "vssvtest117", "vssvtest118", "vssvtest135"
};

static void delete_ssv(void)
{
    int i;

    delete_spv();

    i = 0;

    do
    {
        _unlink(ssv_files[i]);
    }
    while (++i < (sizeof(ssv_files) / sizeof(char *)));
}
#endif

static void cleanup_spv(int keepfiles,
                        int level,
                        ...
                       )
{
    va_list arg;

    if (!keepfiles)
    {
        #if !defined(KEEP_FILES)
        delete_spv();
        #endif
    }

    va_start(arg,
             level
            );

    switch (level)
    {
        case LVL_FINALISE:
        {
            pTaggantContextFree(va_arg(arg,
                                       PTAGGANTCONTEXT
                                      )
                               );
            pTaggantFinalizeLibrary();
        } /* fall through */

        case LVL_FREEDLL:
        {
#ifdef _WIN32
            FreeLibrary(va_arg(arg,
                               HMODULE
                              )
                       );
#else
            /* todo: implement */
#endif
        } /* fall through */

        case LVL_FREEJS:
        {
            free(va_arg(arg,
                        PVOID /* jsfile */
                       )
                );
        } /* fall through */

        case LVL_FREEPE64: /* pefile64 */
        {
            free(va_arg(arg,
                        PVOID
                       )
                );
        } /* fall through */

        case LVL_FREEPE32:
        {
            free(va_arg(arg, /* pefile32 */
                        PVOID
                       )
                );
        } /* fall through */

        case LVL_FREELIC: /* licdata */
        {
            free(va_arg(arg,
                        UNSIGNED8 *
                       )
                );
        } /* fall through */

        case LVL_CLOSEDATA:
        {
            FILE *infile;

            if ((infile = va_arg(arg,
                                 FILE *
                                )
                ) != NULL
               )
            {
                fclose(infile);
            }
        } /* fall through */

        case LVL_MSGONLY:
        {
            int err;

            if ((err = va_arg(arg,
                              int
                             )
                ) != ERR_NONE
               )
            {
                print_tagerr(err);
            }

            break;
        }

        default:
        {
            printf("error: unsupported level %d\n", level);
        }
    }

    va_end(arg);
}

static void cleanup_ssv(int level,
                        ...
                       )
{
    va_list arg;

    #if !defined(KEEP_FILES)
    delete_ssv();
    #endif

    va_start(arg,
             level
            );

    switch (level)
    {
        case LVL_FINALISE:
        {
            pTaggantContextFree(va_arg(arg,
                                       PTAGGANTCONTEXT
                                      )
                               );
            pTaggantFinalizeLibrary();
        } /* fall through */

        case LVL_FREEDLL:
        {
#ifdef _WIN32
            FreeLibrary(va_arg(arg,
                               HMODULE
                              )
                       );
#else
            /* todo: implement */
#endif
            free(va_arg(arg,
                        PVOID /* tsrootdata */
                       )
                );
        } /* fall through */

        case LVL_FREEROOT: /* rootdata */
        {
            free(va_arg(arg,
                        PVOID
                       )
                );
        } /* fall through */

        case LVL_CLOSEDATA:
        {
            FILE *infile;

            if ((infile = va_arg(arg,
                                 FILE *
                                )
                ) != NULL
               )
            {
                fclose(infile);
            }
        } /* fall through */

        case LVL_MSGONLY:
        {
            int err;

            if ((err = va_arg(arg,
                              int
                             )
                ) != ERR_NONE
               )
            {
                print_tagerr(err);
            }

            break;
        }

        default:
        {
            printf("error: unsupported level %d\n", level);
        }
    }

    va_end(arg);
}

static void print_usage(void)
{
    printf("Usage:\n"
           "  test <license.pem> <PE32 file> <PE64 file> <JS file> <IEEERoot.pem>\n"
           "       <TSRoot.pem> <JSON seal> <AppEsteemRoot.pem>\n"
           "       <Sign.pfx> <pfx password>\n"
		   "PE file must be prepared to receive either v1 or v2 Taggant\n"
           "(requires either reserved space containing Taggant footer, or Taggant v1 offset=EOF)\n"
          );
}

static int validate_spv_parms(int argc,
                              _In_reads_(argc) char *argv[],
                              UNSIGNED8 **plicdata,
                              UNSIGNED8 **ppefile32,
                              UNSIGNED64 *ppefile32_len,
                              UNSIGNED64 *ppeobj32_len,
                              UNSIGNED64 *ppefixedobj32_len,
                              UNSIGNED64 *ptag32_off,
                              UNSIGNED32 *ptag32_len,
                              UNSIGNED8 **ppefile64,
                              UNSIGNED64 *ppefile64_len,
                              UNSIGNED64 *ppeobj64_len,
                              UNSIGNED64 *ppefixedobj64_len,
                              UNSIGNED64 *ptag64_off,
                              UNSIGNED32 *ptag64_len,
                              UNSIGNED8 **pjsfile,
                              UNSIGNED64 *pjsfile_len,
                              UNSIGNED8 **paerootdata
                             )
{
    int result;
    UNSIGNED64 tmp_len;

    result = ERR_BADOPEN;

    if (argc == 11)
    {
        if ((result = read_data_file(argv[1],
                                     plicdata,
                                     &tmp_len
                                    )
            ) != ERR_NONE
           )
        {
            cleanup_spv(TRUE,
                        LVL_MSGONLY,
                        result
                       );
        }
        else if ((result = read_data_file(argv[2],
                                          ppefile32,
                                          ppefile32_len
                                         )
                 ) != ERR_NONE
                )
        {
            cleanup_spv(TRUE,
                        LVL_MSGONLY,
                        result
                       );
        }
        else if ((result = object_sizes(*ppefile32,
                                        *ppefile32_len,
                                        ppeobj32_len,
                                        ppefixedobj32_len,
                                        ptag32_off,
                                        ptag32_len
                                       )
                 ) != ERR_NONE
                )
        {
            cleanup_spv(TRUE,
                        LVL_FREEPE32,
                        *ppefile32,
                        *plicdata,
                        0,
                        result
                       );
        }
        else if ((result = read_data_file(argv[3],
                                          ppefile64,
                                          ppefile64_len
                                         )
                 ) != ERR_NONE
                )
        {
            cleanup_spv(TRUE,
                        LVL_FREEPE32,
                        *ppefile32,
                        *plicdata,
                        0,
                        result
                       );
        }
        else if ((result = object_sizes(*ppefile64,
                                        *ppefile64_len,
                                        ppeobj64_len,
                                        ppefixedobj64_len,
                                        ptag64_off,
                                        ptag64_len
                                       )
                 ) != ERR_NONE
                )
        {
            cleanup_spv(TRUE,
                        LVL_FREEPE64,
                        *ppefile64,
                        *ppefile32,
                        *plicdata,
                        0,
                        result
                       );
        }
        else if ((result = read_data_file(argv[4],
                                          pjsfile,
                                          pjsfile_len
                                         )
                 ) != ERR_NONE
                )
        {
            cleanup_spv(TRUE,
                        LVL_FREEPE64,
                        *ppefile64,
                        *ppefile32,
                        *plicdata,
                        0,
                        result
                       );
        }
        else if ((result = read_data_file(argv[8],
                                          paerootdata,
                                          &tmp_len
                                         )
                 ) != ERR_NONE
                )
        {
            cleanup_spv(TRUE,
                        LVL_FREEJS,
                        *pjsfile,
                        *ppefile64,
                        *ppefile32,
                        *plicdata,
                        0,
                        result
                       );
        }
    }

    if (result)
    {
        print_usage();
    }

    return result;
}

static int validate_ssv_parms(_In_ char *argv[],
                              UNSIGNED8 **pprootdata,
                              UNSIGNED8 **pptsrootdata
                             )
{
    int result;
    UNSIGNED64 file_len;

    result = ERR_BADOPEN;

    if ((result = read_data_file(argv[5],
                                 pprootdata,
                                 &file_len
                                )
        ) != ERR_NONE
       )
    {
        cleanup_ssv(TRUE,
                    LVL_MSGONLY,
                    result
                   );
    }
    else if ((result = read_data_file(argv[6],
                                      pptsrootdata,
                                      &file_len
                                     )
             ) != ERR_NONE
            )
    {
        cleanup_ssv(TRUE,
                    LVL_FREEROOT,
                    *pprootdata,
                    0,
                    result
                   );
    }

    if (result)
    {
        print_usage();
    }

    return result;
}

static size_t __stdcall my_fread(_In_ PFILEOBJECT fp,
                                 _Out_writes_bytes_all_(size) PVOID buffer,
                                 size_t size
                                )
{
    return fread(buffer,
                 1,
                 size,
                 (FILE *) fp
                );
}

static int __stdcall my_fseek(_In_ PFILEOBJECT fp,
                              UNSIGNED64 offset,
                              int where
                             )
{
    return fseek((FILE *) fp,
                 (long) offset,
                 where
                );
}

static UNSIGNED64 __stdcall my_ftell(_In_ PFILEOBJECT fp)
{
    return ftell((FILE *) fp);
}

static int init_library(_In_z_ const char *dllname,
                        _Out_writes_(1) HMODULE *plibsxv
                       )
{
#ifdef _WIN32
    HMODULE libsxv;

    if (((libsxv = *plibsxv = LoadLibraryA(dllname)) == NULL)
     || ((pTaggantInitializeLibrary = (UNSIGNED32 (STDCALL *) (TAGGANTFUNCTIONS *,
                                                               UNSIGNED64 *
                                                              )
                                       ) GetProcAddress(libsxv,
                                                        "TaggantInitializeLibrary"
                                                       )
         ) == NULL
        )
     || ((pTaggantContextNewEx = (UNSIGNED32 (STDCALL *) (PTAGGANTCONTEXT *)) GetProcAddress(libsxv,
                                                                                             "TaggantContextNewEx"
                                                                                            )
         ) == NULL
        )
     || ((pTaggantObjectNewEx = (UNSIGNED32 (STDCALL *) (PVOID,
                                                         UNSIGNED64,
                                                         TAGGANTCONTAINER,
                                                         PTAGGANTOBJ *
                                                        )
                                ) GetProcAddress(libsxv,
                                                 "TaggantObjectNewEx"
                                                )
         ) == NULL
        )
     || ((pTaggantPackerInfo = (PPACKERINFO (STDCALL *) (PTAGGANTOBJ)) GetProcAddress(libsxv,
                                                                                      "TaggantPackerInfo"
                                                                                     )
         ) == NULL
        )
     || ((pTaggantContextFree = (void (STDCALL *)(PTAGGANTCONTEXT)) GetProcAddress(libsxv,
                                                                                   "TaggantContextFree"
                                                                                  )
         ) == NULL
        )
     || ((pTaggantObjectFree = (void (STDCALL *)(PTAGGANTOBJ)) GetProcAddress(libsxv,
                                                                              "TaggantObjectFree"
                                                                             )
         ) == NULL
        )
     || ((pTaggantFinalizeLibrary = (void (STDCALL *)(void)) GetProcAddress(libsxv,
                                                                            "TaggantFinalizeLibrary"
                                                                           )
         ) == NULL
        )
       )
    {
        return ERR_BADLIB;
    }

    return ERR_NONE;
#else
    /* todo: implement */
    return TNOTIMPLEMENTED;
#endif
}

static int init_post_library(int mode,
                             UNSIGNED64 reqver,
                             _In_opt_z_ const UNSIGNED8 *licdata,
                             _In_opt_ const UNSIGNED8 *rootdata,
                             _In_opt_ const UNSIGNED8 *tsrootdata,
                             _In_opt_ const UNSIGNED8 *aerootdata,
                             _Inout_updates_(1) PTAGGANTCONTEXT *pcontext
                            )
{
    int result;
    UNSIGNED64 uVersion;
    UNSIGNED64 ltime;

    result = pTaggantInitializeLibrary(NULL, &uVersion);
    if (result != TNOERR)
    {
        return result;
    }

    if (uVersion < reqver)
    {
        return ERR_BADLIBVER;
    }

    if (((mode == MODE_SPV)
      && (!licdata
       || !aerootdata
       || ((result = pTaggantGetLicenseExpirationDate(licdata,
                                                      &ltime
                                                     )
       || ((result = pTaggantCheckCertificate(aerootdata)) != TNOERR)
           ) != TNOERR
          )
         )
        )
     || ((mode == MODE_SSV)
      && (!rootdata
       || !tsrootdata
       || ((result = pTaggantCheckCertificate(rootdata)) != TNOERR)
       || ((result = pTaggantCheckCertificate(tsrootdata)) != TNOERR)
         )
        )
     || ((result = pTaggantContextNewEx(pcontext)) != TNOERR)
       )
    {
        return result;
    }

    /* FILE* is not portable across module boundaries */

    (*pcontext)->FileReadCallBack = my_fread;
    (*pcontext)->FileSeekCallBack = my_fseek;
    (*pcontext)->FileTellCallBack = my_ftell;

    return ERR_NONE;
}

static int init_spv_library(_In_ const char *dllname,
                            _Out_writes_(1) HMODULE *plibspv,
                            UNSIGNED64 reqver,
                            _In_z_ const UNSIGNED8 *licdata,
                            _In_z_ const UNSIGNED8 *aerootdata,
                            PTAGGANTCONTEXT *pcontext
                           )
{
#ifdef _WIN32
    int result;
    HMODULE libspv;

    if ((result = init_library(dllname,
                               plibspv
                              )
        ) != ERR_NONE
       )
    {
        return result;
    }

    if (((pTaggantGetLicenseExpirationDate = (UNSIGNED32 (STDCALL *) (const PVOID,
                                                                      UNSIGNED64 *
                                                                     )
                                             ) GetProcAddress(libspv = *plibspv,
                                                              "TaggantGetLicenseExpirationDate"
                                                             )
         ) == NULL
        )
     || ((pTaggantAddHashRegion = (UNSIGNED32 (STDCALL *) (PTAGGANTOBJ,
                                                           UNSIGNED64,
                                                           UNSIGNED64
                                                          )
                                  ) GetProcAddress(libspv,
                                                   "TaggantAddHashRegion"
                                                  )
         ) == NULL
        )
     || ((pTaggantComputeHashes = (UNSIGNED32 (STDCALL *) (PTAGGANTCONTEXT,
                                                           PTAGGANTOBJ,
                                                           PFILEOBJECT,
                                                           UNSIGNED64,
                                                           UNSIGNED64,
                                                           UNSIGNED32
                                                          )
                                  ) GetProcAddress(libspv,
                                                   "TaggantComputeHashes"
                                                  )
         ) == NULL
        )
     || ((pTaggantPutInfo = (UNSIGNED32 (STDCALL *) (PTAGGANTOBJ,
                                                     ENUMTAGINFO,
                                                     UNSIGNED16,
                                                     PINFO
                                                    )
                            ) GetProcAddress(libspv,
                                             "TaggantPutInfo"
                                            )
         ) == NULL
        )
     || ((pTaggantPutTimestamp = (UNSIGNED32 (STDCALL *) (PTAGGANTOBJ,
                                                          const char *,
                                                          UNSIGNED32
                                                         )
                                 ) GetProcAddress(libspv,
                                                  "TaggantPutTimestamp"
                                                 )
         ) == NULL
        )
     || ((pTaggantPrepare = (UNSIGNED32 (STDCALL *) (PTAGGANTOBJ,
                                                     const PVOID,
                                                     PVOID,
                                                     UNSIGNED32 *
                                                    )
                            ) GetProcAddress(libspv,
                                             "TaggantPrepare"
                                            )
         ) == NULL
        )
     || ((pTaggantCheckCertificate = (UNSIGNED32 (STDCALL *) (const PVOID)
                            ) GetProcAddress(libspv,
                                             "TaggantCheckCertificate"
                                            )
         ) == NULL
        )
       )
    {
        return ERR_BADLIB;
    }
#else
    /* todo: implement */
    return TNOTIMPLEMENTED;
#endif

    return init_post_library(MODE_SPV,
                             reqver,
                             licdata,
                             NULL,
                             NULL,
                             aerootdata,
                             pcontext
                            );
}

static int init_ssv_library(_In_z_ const char *dllname,
                            _Outptr_result_maybenull_ HMODULE *plibssv,
                            UNSIGNED64 reqver,
                            _In_ const UNSIGNED8 *rootdata,
                            _In_ const UNSIGNED8 *tsrootdata,
                            _Inout_ PTAGGANTCONTEXT *pcontext
                           )
{
#ifdef _WIN32
    int result;
    HMODULE libssv;

    if ((result = init_library(dllname,
                               plibssv
                              )
        ) != ERR_NONE
       )
    {
        return result;
    }

    if (((pTaggantCheckCertificate = (UNSIGNED32 (STDCALL *) (const PVOID)) GetProcAddress(libssv = *plibssv,
                                                                                           "TaggantCheckCertificate"
                                                                                          )
         ) == NULL
        )
     || ((pTaggantGetTaggant = (UNSIGNED32 (STDCALL *) (PTAGGANTCONTEXT,
                                                        PFILEOBJECT,
                                                        TAGGANTCONTAINER,
                                                        PTAGGANT *
                                                       )
                               ) GetProcAddress(libssv,
                                                "TaggantGetTaggant"
                                               )
         ) == NULL
        )
     || ((pTaggantValidateSignature = (UNSIGNED32 (STDCALL *) (PTAGGANTOBJ,
                                                               PTAGGANT,
                                                               const PVOID
                                                              )
                                      ) GetProcAddress(libssv,
                                                       "TaggantValidateSignature"
                                                      )
         ) == NULL
        )
     || ((pTaggantGetTimestamp = (UNSIGNED32 (STDCALL *) (PTAGGANTOBJ,
                                                          UNSIGNED64 *,
                                                          const PVOID
                                                         )
                                 ) GetProcAddress(libssv,
                                                  "TaggantGetTimestamp"
                                                 )
         ) == NULL
        )
     || ((pTaggantGetHashMapDoubles = (UNSIGNED16 (STDCALL *) (PTAGGANTOBJ,
                                                               PHASHBLOB_HASHMAP_DOUBLE *
                                                              )
                                      ) GetProcAddress(libssv,
                                                       "TaggantGetHashMapDoubles"
                                                      )
         ) == NULL
        )
     || ((pTaggantValidateHashMap = (UNSIGNED32 (STDCALL *) (PTAGGANTCONTEXT,
                                                             PTAGGANTOBJ,
                                                             PFILEOBJECT
                                                            )
                                    ) GetProcAddress(libssv,
                                                     "TaggantValidateHashMap"
                                                    )
         ) == NULL
        )
     || ((pTaggantGetInfo = (UNSIGNED32 (STDCALL *) (PTAGGANTOBJ,
                                                     ENUMTAGINFO,
                                                     UNSIGNED32 *,
                                                     PINFO
                                                    )
                            ) GetProcAddress(libssv,
                                             "TaggantGetInfo"
                                            )
         ) == NULL
        )
     || ((pTaggantValidateDefaultHashes = (UNSIGNED32 (STDCALL *) (PTAGGANTCONTEXT,
                                                                   PTAGGANTOBJ,
                                                                   PFILEOBJECT,
                                                                   UNSIGNED64,
                                                                   UNSIGNED64
                                                                  )
                                          ) GetProcAddress(libssv,
                                                           "TaggantValidateDefaultHashes"
                                                          )
         ) == NULL
        )
     || ((pTaggantFreeTaggant = (UNSIGNED32 (STDCALL *) (PTAGGANT)) GetProcAddress(libssv,
                                                                                   "TaggantFreeTaggant"
                                                                                  )
         ) == NULL
        )
       )
    {
        return ERR_BADLIB;
    }
#else
    /* todo: implement */
    return TNOTIMPLEMENTED;
#endif

    return init_post_library(MODE_SSV,
                             reqver,
                             NULL,
                             rootdata,
                             tsrootdata,
                             NULL,
                             pcontext
                            );
}

static int test_spv_v101(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         _In_reads_(pefile_len) const UNSIGNED8 *pefile,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 pefile_len,
                         UNSIGNED64 file_len,
                         UNSIGNED64 tag_off,
                         UNSIGNED32 tag_len
                        )
{
    int result;

    printf(PR_WIDTH, "v1test01: add v1 Taggant to 32-bit PE file containing no Taggant and no overlay:");

    result = create_tmp_v1_taggant("v1test01",
                                   context,
                                   licdata,
                                   pefile,
                                   peobj_len,
                                   pefile_len,
                                   file_len,
                                   tag_off,
                                   tag_len,
                                   FALSE,
                                   TRUE
                                  );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v102(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 pefile_len
                        )
{
    int result;

    printf(PR_WIDTH, "v1test02: add v1 Taggant to 32-bit PE file containing v1 Taggant and no overlay:");

    result = create_v1_v1_taggant("v1test01",
                                  "v1test02",
                                  context,
                                  licdata,
                                  peobj_len,
                                  pefile_len,
                                  FALSE
                                 );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v103(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 tag_off
                        )
{
    int result;

    printf(PR_WIDTH, "v1test03: add v1 Taggant to 32-bit PE file containing v2 Taggant and no overlay:");

    result = create_tmp_v1_v2_taggant("v1test01",
                                      "v1test03",
                                      context,
                                      licdata,
                                      peobj_len,
                                      tag_off,
                                      FALSE
                                     );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v104(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         _In_reads_(pefile_len) const UNSIGNED8 *pefile,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 pefile_len,
                         UNSIGNED64 file_len,
                         UNSIGNED64 tag_off,
                         UNSIGNED32 tag_len
                        )
{
    int result;

    printf(PR_WIDTH, "v1test04: add v1 Taggant to 64-bit PE file containing no Taggant and no overlay:");

    result = create_tmp_v1_taggant("v1test04",
                                   context,
                                   licdata,
                                   pefile,
                                   peobj_len,
                                   pefile_len,
                                   file_len,
                                   tag_off,
                                   tag_len,
                                   FALSE,
                                   TRUE
                                  );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v105(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 pefile_len
                        )
{
    int result;

    printf(PR_WIDTH, "v1test05: add v1 Taggant to 64-bit PE file containing v1 Taggant and no overlay:");

    result = create_v1_v1_taggant("v1test04",
                                  "v1test05",
                                  context,
                                  licdata,
                                  peobj_len,
                                  pefile_len,
                                  FALSE
                                 );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v106(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 tag_off
                        )
{
    int result;

    printf(PR_WIDTH, "v1test06: add v1 Taggant to 64-bit PE file containing v2 Taggant and no overlay:");

    result = create_tmp_v1_v2_taggant("v1test04",
                                      "v1test06",
                                      context,
                                      licdata,
                                      peobj_len,
                                      tag_off,
                                      FALSE
                                     );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v107(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 tag_off
                        )
{
    int result;

    printf(PR_WIDTH, "v1test07: add v1 Taggant to 32-bit PE file containing no Taggant and overlay:");

    result = append_v1_taggant("v1test01",
                               "v1test07",
                               context,
                               licdata,
                               peobj_len,
                               tag_off
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v108(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 pefile_len
                        )
{
    int result;
    printf(PR_WIDTH, "v1test08: add v1 Taggant to 32-bit PE file containing v1 Taggant and overlay:");

    result = create_v1_v1_taggant("v1test07",
                                  "v1test08",
                                  context,
                                  licdata,
                                  peobj_len,
                                  pefile_len,
                                  FALSE
                                 );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v109(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 tag_off
                        )
{
    int result;

    printf(PR_WIDTH, "v1test09: add v1 Taggant to 32-bit PE file containing v2 Taggant and overlay:");

    result = append_v1_v2_taggant("v1test01",
                                  "v1test09",
                                  context,
                                  licdata,
                                  peobj_len,
                                  tag_off
                                 );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v110(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 tag_off
                        )
{
    int result;

    printf(PR_WIDTH, "v1test10: add v1 Taggant to 64-bit PE file containing no Taggant and overlay:");

    result = append_v1_taggant("v1test04",
                               "v1test10",
                               context,
                               licdata,
                               peobj_len,
                               tag_off
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v111(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 pefile_len
                        )
{
    int result;

    printf(PR_WIDTH, "v1test11: add v1 Taggant to 64-bit PE file containing v1 Taggant and overlay:");

    result = create_v1_v1_taggant("v1test10",
                                  "v1test11",
                                  context,
                                  licdata,
                                  peobj_len,
                                  pefile_len,
                                  FALSE
                                 );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v112(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 tag_off
                        )
{
    int result;

    printf(PR_WIDTH, "v1test12: add v1 Taggant to 64-bit PE file containing v2 Taggant and overlay:");

    result = append_v1_v2_taggant("v1test04",
                                  "v1test12",
                                  context,
                                  licdata,
                                  peobj_len,
                                  tag_off
                                 );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v113(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata
                        )
{
    int result;

    printf(PR_WIDTH, "v1test13: add v1 Taggant to 32-bit PE file containing tampered v1 Taggant:");

    result = create_tampered_v1_image("v1test01",
                                      "v1tampered1_32",
                                      "v1test13",
                                      context,
                                      licdata,
                                      1,
                                      0
                                     );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v114(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 tag_off
                        )
{
    int result;

    printf(PR_WIDTH, "v1test14: add v1 Taggant to 32-bit PE file containing tampered v2 Taggant:");

    result = create_tampered_v1_v2_image("v1test01",
                                         "v1test14",
                                         "v1test14",
                                         context,
                                         licdata,
                                         peobj_len,
                                         tag_off,
                                         FALSE,
                                         (UNSIGNED64) -0x100
                                        );
    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v115(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata
                        )
{
    int result;

    printf(PR_WIDTH, "v1test15: add v1 Taggant to 64-bit PE file containing tampered v1 Taggant:");

    result = create_tampered_v1_image("v1test04",
                                      "v1tampered1_64",
                                      "v1test15",
                                      context,
                                      licdata,
                                      1,
                                      0
                                     );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v116(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 tag_off
                        )
{
    int result;

    printf(PR_WIDTH, "v1test16: add v1 Taggant to 64-bit PE file containing tampered v2 Taggant:");

    result = create_tampered_v1_v2_image("v1test04",
                                         "v1test16",
                                         "v1test16",
                                         context,
                                         licdata,
                                         peobj_len,
                                         tag_off,
                                         FALSE,
                                         (UNSIGNED64) -0x100
                                        );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v117(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata
                        )
{
    int result;

    printf(PR_WIDTH, "v1test17: add v1 Taggant to 32-bit PE file containing good v1 Taggant and tampered image:");

    result = create_tampered_v1_image("v1tampered1_32",
                                      "v1tampered2_32",
                                      "v1test17",
                                      context,
                                      licdata,
                                      -1,
                                      1
                                     );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v118(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 tag_off
                        )
{
    int result;

    printf(PR_WIDTH, "v1test18: add v1 Taggant to 32-bit PE file containing good v2 Taggant and tampered image:");

    result = create_tampered_v1_v2_image("v1test01",
                                         "v1test18",
                                         "v1test18",
                                         context,
                                         licdata,
                                         peobj_len,
                                         tag_off,
                                         FALSE,
                                         2
                                        );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v119(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata
                        )
{
    int result;

    printf(PR_WIDTH, "v1test19: add v1 Taggant to 64-bit PE file containing good v1 Taggant and tampered image:");

    result = create_tampered_v1_image("v1tampered1_64",
                                      "v1tampered2_64",
                                      "v1test19",
                                      context,
                                      licdata,
                                      -1,
                                      1
                                     );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v120(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 tag_off
                        )
{
    int result;

    printf(PR_WIDTH, "v1test20: add v1 Taggant to 64-bit PE file containing good v2 Taggant and tampered image:");

    result = create_tampered_v1_v2_image("v1test04",
                                         "v1test20",
                                         "v1test20",
                                         context,
                                         licdata,
                                         peobj_len,
                                         tag_off,
                                         FALSE,
                                         2
                                        );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v121(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         _In_reads_(pefile_len) const UNSIGNED8 *pefile,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 pefile_len,
                         UNSIGNED64 file_len,
                         UNSIGNED64 tag_off,
                         UNSIGNED32 tag_len
                        )
{
    int result;

    printf(PR_WIDTH, "v1test21: add v1 Taggant HashMap to 32-bit PE file containing no Taggant:");

    result = create_tmp_v1_taggant("v1test21",
                                   context,
                                   licdata,
                                   pefile,
                                   peobj_len,
                                   pefile_len,
                                   file_len,
                                   tag_off,
                                   tag_len,
                                   TRUE,
                                   FALSE
                                  );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v122(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         _In_reads_(pefile_len) const UNSIGNED8 *pefile,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 pefile_len,
                         UNSIGNED64 file_len,
                         UNSIGNED64 tag_off,
                         UNSIGNED32 tag_len
                        )
{
    int result;

    printf(PR_WIDTH, "v1test22: add v1 Taggant HashMap to 64-bit PE file containing no Taggant:");

    result = create_tmp_v1_taggant("v1test22",
                                   context,
                                   licdata,
                                   pefile,
                                   peobj_len,
                                   pefile_len,
                                   file_len,
                                   tag_off,
                                   tag_len,
                                   TRUE,
                                   FALSE
                                  );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v123(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         _In_reads_(pefile_len) const UNSIGNED8 *pefile,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 pefile_len,
                         UNSIGNED64 file_len,
                         UNSIGNED64 tag_off,
                         UNSIGNED32 tag_len
                        )
{
    int result;

    printf(PR_WIDTH, "v1test23: add v1 Taggant to 32-bit PE file containing good v1 Taggant and broken HMH and good image:");

    result = create_bad_v1_hmh("v1badhmh_32",
                               "v1test23",
                               context,
                               licdata,
                               pefile,
                               peobj_len,
                               pefile_len,
                               file_len,
                               tag_off,
                               tag_len
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v124(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 tag_off
                        )
{
    int result;

    printf(PR_WIDTH, "v1test24: add v1 Taggant to 32-bit PE file containing good v2 Taggant and broken HMH and good image:");

    result = create_tampered_v1_v2_image("v1test01",
                                         "v2badhmh_32",
                                         "v1test24",
                                         context,
                                         licdata,
                                         peobj_len,
                                         tag_off,
                                         TRUE,
                                         0
                                        );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v125(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         _In_reads_(pefile_len) const UNSIGNED8 *pefile,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 pefile_len,
                         UNSIGNED64 file_len,
                         UNSIGNED64 tag_off,
                         UNSIGNED32 tag_len
                        )
{
    int result;

    printf(PR_WIDTH, "v1test25: add v1 Taggant to 64-bit PE file containing good v1 Taggant and broken HMH and good image:");

    result = create_bad_v1_hmh("v1badhmh_64",
                               "v1test25",
                               context,
                               licdata,
                               pefile,
                               peobj_len,
                               pefile_len,
                               file_len,
                               tag_off,
                               tag_len
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v126(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 tag_off
                        )
{
    int result;

    printf(PR_WIDTH, "v1test26: add v1 Taggant to 64-bit PE file containing good v2 Taggant and broken HMH and good image:");

    result = create_tampered_v1_v2_image("v1test04",
                                         "v2badhmh_64",
                                         "v1test26",
                                         context,
                                         licdata,
                                         peobj_len,
                                         tag_off,
                                         TRUE,
                                         0
                                        );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v127(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         _In_reads_(pefile_len) const UNSIGNED8 *pefile,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 pefile_len,
                         UNSIGNED64 file_len,
                         UNSIGNED64 tag_off,
                         UNSIGNED32 tag_len
                        )
{
    int result;

    printf(PR_WIDTH, "v1test27: add v1 Taggant without timestamp to 32-bit PE file:");

    result = create_tmp_v1_taggant("v1test27",
                                   context,
                                   licdata,
                                   pefile,
                                   peobj_len,
                                   pefile_len,
                                   file_len,
                                   tag_off,
                                   tag_len,
                                   FALSE,
                                   FALSE
                                  );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v128(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 pefile_len
                        )
{
    int result;

    printf(PR_WIDTH, "v1test28: add v1 Taggant with timestamp to 32-bit PE file containing v1 Taggant without timestamp:");

    result = create_v1_v1_taggant("v1test27",
                                  "v1test28",
                                  context,
                                  licdata,
                                  peobj_len,
                                  pefile_len,
                                  TRUE
                                 );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;

}

static int test_spv_v129(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         _In_reads_(pefile_len) const UNSIGNED8 *pefile,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 pefile_len,
                         UNSIGNED64 tag_off,
                         UNSIGNED32 tag_len
                        )
{
    int result;

    printf(PR_WIDTH, "v1test29: add v1 Taggant with timestamp to 32-bit PE file containing v2 Taggant without timestamp:");

    if ((result = create_tmp_v2_taggant("v1test29",
                                        context,
                                        TAGGANT_PEFILE,
                                        licdata,
                                        pefile,
                                        peobj_len,
                                        pefile_len,
                                        FALSE,
                                        FALSE
                                       )
        ) == ERR_NONE
       )
    {
        result = create_v1_taggant("v1test29",
                                   context,
                                   licdata,
                                   peobj_len,
                                   pefile_len,
                                   tag_off,
                                   tag_len,
                                   FALSE,
                                   FALSE,
                                   TRUE
                                  );
    }

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v130(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         _In_reads_(pefile_len) const UNSIGNED8 *pefile,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 pefile_len,
                         UNSIGNED64 file_len,
                         UNSIGNED64 tag_off,
                         UNSIGNED32 tag_len
                        )
{
    int result;

    printf(PR_WIDTH, "v1test30: add v1 Taggant without timestamp to 64-bit PE file:");

    result = create_tmp_v1_taggant("v1test30",
                                   context,
                                   licdata,
                                   pefile,
                                   peobj_len,
                                   pefile_len,
                                   file_len,
                                   tag_off,
                                   tag_len,
                                   FALSE,
                                   FALSE
                                  );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v131(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 pefile_len
                        )
{
    int result;

    printf(PR_WIDTH, "v1test31: add v1 Taggant with timestamp to 64-bit PE file containing v1 Taggant without timestamp:");

    result = create_v1_v1_taggant("v1test30",
                                  "v1test31",
                                  context,
                                  licdata,
                                  peobj_len,
                                  pefile_len,
                                  TRUE
                                 );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v132(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         _In_reads_(pefile_len) const UNSIGNED8 *pefile,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 pefile_len,
                         UNSIGNED64 tag_off,
                         UNSIGNED32 tag_len
                        )
{
    int result;

    printf(PR_WIDTH, "v1test32: add v1 Taggant with timestamp to 64-bit PE file containing v2 Taggant without timestamp:");

    if ((result = create_tmp_v2_taggant("v1test32",
                                        context,
                                        TAGGANT_PEFILE,
                                        licdata,
                                        pefile,
                                        peobj_len,
                                        pefile_len,
                                        FALSE,
                                        FALSE
                                       )
        ) == ERR_NONE
       )
    {
        result = create_v1_taggant("v1test32",
                                   context,
                                   licdata,
                                   peobj_len,
                                   pefile_len,
                                   tag_off,
                                   tag_len,
                                   FALSE,
                                   FALSE,
                                   TRUE
                                  );
    }

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v133(void)
{
    int result;
    PTAGGANTOBJ object;

    printf(PR_WIDTH, "v1test33: add data to v1 ExtraBlob:");
    object = NULL;

    if ((result = pTaggantObjectNewEx(NULL,
                                      TAGGANT_LIBRARY_VERSION1,
                                      TAGGANT_PEFILE,
                                      &object
                                     )
        ) == TNOERR
       )
    {
        result = pTaggantPutInfo(object,
                                 ECONTRIBUTORLIST,
                                 1,
                                 (PINFO) &result /* anything */
                                );
        pTaggantObjectFree(object);

        if (result == TNOERR)
        {
            result = ERR_BADLIB;
        }
        else if (result == TERRORKEY)
        {
            result = ERR_NONE;
        }
    }

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v134(void)
{
    int result;
    PTAGGANTOBJ object;

    printf(PR_WIDTH, "v1test34: add v1 Taggant to JS file:");

    object = NULL;

    result = pTaggantObjectNewEx(NULL,
                                 TAGGANT_LIBRARY_VERSION1,
                                 TAGGANT_JSFILE,
                                 &object
                                );
    pTaggantObjectFree(object);

    if (result == TNOERR)
    {
        result = ERR_BADLIB;
    }
    else if (result == TTYPE)
    {
        result = ERR_NONE;
    }

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v201(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         _In_reads_(pefile_len) const UNSIGNED8 *pefile,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 pefile_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test01: add v2 Taggant to 32-bit PE file containing no Taggant and no overlay:");

    result = create_tmp_v2_taggant("v2test01",
                                   context,
                                   TAGGANT_PEFILE,
                                   licdata,
                                   pefile,
                                   peobj_len,
                                   pefile_len,
                                   FALSE,
                                   TRUE
                                  );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v202(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test02: add v2 Taggant to 32-bit PE file containing v1 Taggant and no overlay:");

    result = create_v2_taggant_taggant("v1test01",
                                       "v2test02",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       peobj_len,
                                       TRUE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v203(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test03: add v2 Taggant to 32-bit PE file containing v2 Taggant and no overlay:");

    result = create_v2_taggant_taggant("v2test01",
                                       "v2test03",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       peobj_len,
                                       TRUE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v204(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test04: add v2 Taggant to 32-bit PE file containing v2 Taggant and v1 Taggant and no overlay:");

    result = create_v2_taggant_taggant("v2test02",
                                       "v2test04",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       peobj_len,
                                       TRUE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v205(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         _In_reads_(pefile_len) const UNSIGNED8 *pefile,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 pefile_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test05: add v2 Taggant to 64-bit PE file containing no Taggant and no overlay:");

    result = create_tmp_v2_taggant("v2test05",
                                   context,
                                   TAGGANT_PEFILE,
                                   licdata,
                                   pefile,
                                   peobj_len,
                                   pefile_len,
                                   FALSE,
                                   TRUE
                                  );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v206(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test06: add v2 Taggant to 64-bit PE file containing v1 Taggant and no overlay:");

    result = create_v2_taggant_taggant("v1test04",
                                       "v2test06",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       peobj_len,
                                       TRUE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v207(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test07: add v2 Taggant to 64-bit PE file containing v2 Taggant and no overlay:");

    result = create_v2_taggant_taggant("v2test05",
                                       "v2test07",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       peobj_len,
                                       TRUE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v208(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test08: add v2 Taggant to 64-bit PE file containing v2 Taggant and v1 Taggant and no overlay:");

    result = create_v2_taggant_taggant("v2test06",
                                       "v2test08",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       peobj_len,
                                       TRUE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v209(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         _In_reads_(pefile_len) const UNSIGNED8 *pefile,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 pefile_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test09: add v2 Taggant to 32-bit PE file containing no Taggant and overlay:");

    result = append_v2_taggant("v2test09",
                               context,
                               licdata,
                               pefile,
                               peobj_len,
                               pefile_len
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v210(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test10: add v2 Taggant to 32-bit PE file containing v1 Taggant and overlay:");

    result = create_v2_taggant_taggant("v1test07",
                                       "v2test10",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       peobj_len,
                                       FALSE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v211(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test11: add v2 Taggant to 32-bit PE file containing v2 Taggant and overlay:");

    result = create_v2_taggant_taggant("v2test09",
                                       "v2test11",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       peobj_len,
                                       FALSE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v212(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test12: add v2 Taggant to 32-bit PE file containing v2 Taggant and v1 Taggant and overlay:");

    result = create_v2_taggant_taggant("v2test10",
                                       "v2test12",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       peobj_len,
                                       FALSE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v213(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         _In_reads_(pefile_len) const UNSIGNED8 *pefile,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 pefile_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test13: add v2 Taggant to 64-bit PE file containing no Taggant and overlay:");

    result = append_v2_taggant("v2test13",
                               context,
                               licdata,
                               pefile,
                               peobj_len,
                               pefile_len
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v214(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test14: add v2 Taggant to 64-bit PE file containing v1 Taggant and overlay:");

    result = create_v2_taggant_taggant("v1test10",
                                       "v2test14",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       peobj_len,
                                       FALSE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v215(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test15: add v2 Taggant to 64-bit PE file containing v2 Taggant and overlay:");

    result = create_v2_taggant_taggant("v2test13",
                                       "v2test15",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       peobj_len,
                                       FALSE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v216(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test16: add v2 Taggant to 64-bit PE file containing v2 Taggant and v1 Taggant and overlay:");

    result = create_v2_taggant_taggant("v2test14",
                                       "v2test16",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       peobj_len,
                                       FALSE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

#if defined(CSA_MODE)
static int test_spv_v217(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test17: add v2 Taggant to 32-bit PE file containing tampered v1 Taggant:");

    if ((result = create_v2_taggant_taggant("v1tampered1_32",
                                            "v2test17",
                                            context,
                                            TAGGANT_PEFILE,
                                            licdata,
                                            peobj_len,
                                            FALSE,
                                            FALSE
                                           )
        ) == ERR_NONE
       )
    {
        result = ERR_BADLIB;
    }
    else if (result == TBADKEY)
    {
        result = ERR_NONE;
    }

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}
#endif

static int test_spv_v218(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

#if defined(CSA_MODE)
    printf(PR_WIDTH, "v2test18: add v2 Taggant to 32-bit PE file containing tampered v2 Taggant:");

    if ((result = create_tampered_v2_image("v2test01",
                                           "v2tampered1_32",
                                           "v2test18",
                                           context,
                                           licdata,
                                           peobj_len,
                                           1,
                                           0,
                                           FALSE
                                          )
        ) == ERR_NONE
       )
    {
        result = ERR_BADLIB;
    }
    else if (result == TBADKEY)
    {
        result = ERR_NONE;
    }
#else
    context;
    licdata;
    peobj_len;

    printf(PR_WIDTH, "v2test18: create 32-bit PE file containing tampered v2 Taggant:");

    result = create_tampered_v2_image("v2test01",
                                      "v2tampered1_32",
                                      NULL,
                                      NULL,
                                      NULL,
                                      0,
                                      1,
                                      0,
                                      FALSE
                                     );
#endif

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

#if defined(CSA_MODE)
static int test_spv_v219(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test19: add v2 Taggant to 64-bit PE file containing tampered v1 Taggant:");

    if ((result = create_v2_taggant_taggant("v1tampered1_64",
                                            "v2test19",
                                            context,
                                            TAGGANT_PEFILE,
                                            licdata,
                                            peobj_len,
                                            FALSE,
                                            FALSE
                                           )
        ) == ERR_NONE
       )
    {
        result = ERR_BADLIB;
    }
    else if (result == TBADKEY)
    {
        result = ERR_NONE;
    }

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}
#endif

static int test_spv_v220(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

#if defined(CSA_MODE)
    printf(PR_WIDTH, "v2test20: add v2 Taggant to 64-bit PE file containing tampered v2 Taggant:");

    if ((result = create_tampered_v2_image("v2test05",
                                           "v2tampered1_64",
                                           "v2test20",
                                           context,
                                           licdata,
                                           peobj_len,
                                           1,
                                           0,
                                           FALSE
                                          )
        ) == ERR_NONE
       )
    {
        result = ERR_BADLIB;
    }
    else if (result == TBADKEY)
    {
        result = ERR_NONE;
    }
#else
    context;
    licdata;
    peobj_len;

    printf(PR_WIDTH, "v2test20: create 64-bit PE file containing tampered v2 Taggant:");

    result = create_tampered_v2_image("v2test05",
                                      "v2tampered1_64",
                                      NULL,
                                      NULL,
                                      NULL,
                                      0,
                                      1,
                                      0,
                                      FALSE
                                     );
#endif

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

#if defined(CSA_MODE)
static int test_spv_v221(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test21: add v2 Taggant to 32-bit PE file containing good v1 Taggant and tampered image:");

    if ((result = create_v2_taggant_taggant("v1tampered2_32",
                                            "v2test21",
                                            context,
                                            TAGGANT_PEFILE,
                                            licdata,
                                            peobj_len,
                                            FALSE,
                                            FALSE
                                           )
        ) == ERR_NONE
       )
    {
        result = ERR_BADLIB;
    }
    else if (result == TBADKEY)
    {
        result = ERR_NONE;
    }

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v222(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test22: add v2 Taggant to 32-bit PE file containing good v2 Taggant and tampered image:");

    if ((result = create_tampered_v2_image("v2tampered1_32",
                                           "v2tampered2_32",
                                           "v2test22",
                                           context,
                                           licdata,
                                           peobj_len,
                                           -1,
                                           1,
                                           FALSE
                                          )
        ) == ERR_NONE
       )
    {
        result = ERR_BADLIB;
    }
    else if (result == TBADKEY)
    {
        result = ERR_NONE;
    }

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v223(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test23: add v2 Taggant to 64-bit PE file containing good v1 Taggant and tampered image:");

    if ((result = create_v2_taggant_taggant("v1tampered2_64",
                                            "v2test23",
                                            context,
                                            TAGGANT_PEFILE,
                                            licdata,
                                            peobj_len,
                                            FALSE,
                                            FALSE
                                           )
        ) == ERR_NONE
       )
    {
        result = ERR_BADLIB;
    }
    else if (result == TBADKEY)
    {
        result = ERR_NONE;
    }

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v224(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test24: add v2 Taggant to 64-bit PE file containing good v2 Taggant and tampered image:");

    if ((result = create_tampered_v2_image("v2tampered1_64",
                                           "v2tampered2_64",
                                           "v2test24",
                                           context,
                                           licdata,
                                           peobj_len,
                                           -1,
                                           1,
                                           FALSE
                                          )
        ) == ERR_NONE
       )
    {
        result = ERR_BADLIB;
    }
    else if (result == TBADKEY)
    {
        result = ERR_NONE;
    }

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}
#endif

static int test_spv_v225(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         _In_reads_(pefile_len) const UNSIGNED8 *pefile,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 pefile_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test25: add v2 Taggant HashMap to 32-bit PE file containing no Taggant:");

    result = create_tmp_v2_taggant("v2test25",
                                   context,
                                   TAGGANT_PEFILE,
                                   licdata,
                                   pefile,
                                   peobj_len,
                                   pefile_len,
                                   TRUE,
                                   FALSE
                                  );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v226(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test26: add v2 Taggant to 32-bit PE file containing v1 HashMap Taggant:");

    result = create_v2_taggant_taggant("v1test21",
                                       "v2test26",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       peobj_len,
                                       FALSE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v227(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test27: add v2 Taggant to 32-bit PE file containing v2 HashMap Taggant:");

    result = create_v2_taggant_taggant("v2test25",
                                       "v2test27",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       peobj_len,
                                       FALSE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v228(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test28: add v2 Taggant to 32-bit PE file containing v2 Taggant and v1 HashMap Taggant:");

    result = create_v2_taggant_taggant("v2test26",
                                       "v2test28",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       peobj_len,
                                       FALSE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v229(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         _In_reads_(pefile_len) const UNSIGNED8 *pefile,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 pefile_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test29: add v2 Taggant HashMap to 64-bit PE file containing no Taggant:");

    result = create_tmp_v2_taggant("v2test29",
                                   context,
                                   TAGGANT_PEFILE,
                                   licdata,
                                   pefile,
                                   peobj_len,
                                   pefile_len,
                                   TRUE,
                                   FALSE
                                  );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v230(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test30: add v2 Taggant to 64-bit PE file containing v1 HashMap Taggant:");

    result = create_v2_taggant_taggant("v1test22",
                                       "v2test30",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       peobj_len,
                                       FALSE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v231(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test31: add v2 Taggant to 64-bit PE file containing v2 HashMap Taggant:");

    result = create_v2_taggant_taggant("v2test29",
                                       "v2test31",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       peobj_len,
                                       FALSE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v232(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test32: add v2 Taggant to 64-bit PE file containing v2 Taggant and v1 HashMap Taggant:");

    result = create_v2_taggant_taggant("v2test30",
                                       "v2test32",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       peobj_len,
                                       FALSE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

#if defined(CSA_MODE)
static int test_spv_v233(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test33: add v2 Taggant to 32-bit PE file containing good v1 Taggant and broken HMH and good image:");

    result = create_v2_taggant_taggant("v1badhmh_32",
                                       "v2test33",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       peobj_len,
                                       FALSE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v234(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test34: add v2 Taggant to 32-bit PE file containing good v2 Taggant and broken HMH and good image:");

    result = create_bad_v2_hmh("v2badhmh_32",
                               "v2test34",
                               context,
                               licdata,
                               peobj_len
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v235(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test35: add v2 Taggant to 64-bit PE file containing good v1 Taggant and broken HMH and good image:");

    result = create_v2_taggant_taggant("v1badhmh_64",
                                       "v2test35",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       peobj_len,
                                       FALSE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v236(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test36: add v2 Taggant to 64-bit PE file containing good v2 Taggant and broken HMH and good image:");

    result = create_bad_v2_hmh("v2badhmh_64",
                               "v2test36",
                               context,
                               licdata,
                               peobj_len
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}
#endif

static int test_spv_v237(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         _In_reads_(pefile_len) const UNSIGNED8 *pefile,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 pefile_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test37: add v2 Taggant without timestamp to 32-bit PE file:");

    result = create_tmp_v2_taggant("v2test37",
                                   context,
                                   TAGGANT_PEFILE,
                                   licdata,
                                   pefile,
                                   peobj_len,
                                   pefile_len,
                                   FALSE,
                                   FALSE
                                  );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v238(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test38: add v2 Taggant with timestamp to 32-bit PE file containing v1 Taggant without timestamp:");

    result = create_v2_taggant_taggant("v1test27",
                                       "v2test38",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       peobj_len,
                                       TRUE,
                                       FALSE
                                      );
 
    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v239(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;
 
    printf(PR_WIDTH, "v2test39: add v2 Taggant with timestamp to 32-bit PE file containing v2 Taggant without timestamp:");

    result = create_v2_taggant_taggant("v2test37",
                                       "v2test39",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       peobj_len,
                                       TRUE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v240(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test40: add v2 Taggant with timestamp to 32-bit PE file containing v2 Taggant with timestamp and v1 Taggant without timestamp:");

    result = create_v2_taggant_taggant("v2test38",
                                       "v2test40",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       peobj_len,
                                       TRUE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v241(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test41: add v2 Taggant without timestamp to 32-bit PE file containing v1 Taggant with timestamp:");

    result = create_v2_taggant_taggant("v1test01",
                                       "v2test41",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       peobj_len,
                                       FALSE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v242(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test42: add v2 Taggant without timestamp to 32-bit PE file containing v2 Taggant with timestamp:");

    result = create_v2_taggant_taggant("v2test01",
                                       "v2test42",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       peobj_len,
                                       FALSE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v243(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test43: add v2 Taggant with timestamp to 32-bit PE file containing v2 Taggant without timestamp and v1 Taggant with timestamp:");

    result = create_v2_taggant_taggant("v2test41",
                                       "v2test43",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       peobj_len,
                                       TRUE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v244(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         _In_reads_(pefile_len) const UNSIGNED8 *pefile,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 pefile_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test44: add v2 Taggant without timestamp to 64-bit PE file:");

    result = create_tmp_v2_taggant("v2test44",
                                   context,
                                   TAGGANT_PEFILE,
                                   licdata,
                                   pefile,
                                   peobj_len,
                                   pefile_len,
                                   FALSE,
                                   FALSE
                                  );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v245(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test45: add v2 Taggant with timestamp to 64-bit PE file containing v1 Taggant without timestamp:");

    result = create_v2_taggant_taggant("v1test30",
                                       "v2test45",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       peobj_len,
                                       TRUE,
                                       FALSE
                                      );
 
    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v246(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;
 
    printf(PR_WIDTH, "v2test46: add v2 Taggant with timestamp to 64-bit PE file containing v2 Taggant without timestamp:");

    result = create_v2_taggant_taggant("v2test44",
                                       "v2test46",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       peobj_len,
                                       TRUE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v247(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test47: add v2 Taggant with timestamp to 64-bit PE file containing v2 Taggant with timestamp and v1 Taggant without timestamp:");

    result = create_v2_taggant_taggant("v2test45",
                                       "v2test47",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       peobj_len,
                                       TRUE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v248(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test48: add v2 Taggant without timestamp to 64-bit PE file containing v1 Taggant with timestamp:");

    result = create_v2_taggant_taggant("v1test04",
                                       "v2test48",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       peobj_len,
                                       FALSE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v249(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test49: add v2 Taggant without timestamp to 64-bit PE file containing v2 Taggant with timestamp:");

    result = create_v2_taggant_taggant("v2test05",
                                       "v2test49",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       peobj_len,
                                       FALSE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v250(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test50: add v2 Taggant with timestamp to 64-bit PE file containing v2 Taggant without timestamp and v1 Taggant with timestamp:");

    result = create_v2_taggant_taggant("v2test48",
                                       "v2test50",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       peobj_len,
                                       TRUE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v251(_In_z_ const UNSIGNED8 *licdata,
                         _In_reads_(pefile_len) const UNSIGNED8 *pefile,
                         UNSIGNED64 pefile_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test51: add duplicated tag to 32-bit v2 ExtraBlob:");

    result = duplicate_tag("v2test51",
                           licdata,
                           pefile,
                           pefile_len
                          );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v252(_In_z_ const UNSIGNED8 *licdata,
                         _In_reads_(pefile_len) const UNSIGNED8 *pefile,
                         UNSIGNED64 pefile_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test52: add duplicated tag to 64-bit v2 ExtraBlob:");

    result = duplicate_tag("v2test52",
                           licdata,
                           pefile,
                           pefile_len
                          );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v253(void)
{
    int result;
    char *buffer;
    PTAGGANTOBJ object;

    printf(PR_WIDTH, "v2test53: add single data of > 64kb to v2 ExtraBlob:");

    if ((buffer = (char *) malloc(0xffff)) == NULL)
    {
        return TMEMORY;
    }

    object = NULL;

    if ((result = pTaggantObjectNewEx(NULL,
                                      TAGGANT_LIBRARY_VERSION2,
                                      TAGGANT_PEFILE,
                                      &object
                                     )
         ) == TNOERR
        )
    {
        result = pTaggantPutInfo(object,
                                 ECONTRIBUTORLIST,
                                 0xffff,
                                 buffer
                                );
        pTaggantObjectFree(object);
       
        if (result == TNOERR)
        {
            result = ERR_BADLIB;
        }
        else if (result == TINSUFFICIENTBUFFER)
        {
            result = ERR_NONE;
        }
    }

    free(buffer);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v254(void)
{
    int result;
    char *buffer;
    PTAGGANTOBJ object;

    printf(PR_WIDTH, "v2test54: add total data of > 64kb to v2 ExtraBlob:");

    if ((buffer = (char *) malloc(0x10000)) == NULL)
    {
        return TMEMORY;
    }

    object = NULL;

    if (((result = pTaggantObjectNewEx(NULL,
                                       TAGGANT_LIBRARY_VERSION2,
                                       TAGGANT_PEFILE,
                                       &object
                                      )
         ) == TNOERR
        )
     && ((result = pTaggantPutInfo(object,
                                   (ENUMTAGINFO) 0x8000,
                                   (54 * 1024) - 4,
                                   buffer
                                  )
         ) == ERR_NONE
        )
     && ((result = pTaggantPutInfo(object,
                                   (ENUMTAGINFO) 0x8002,
                                   (4 * 1024) - 4,
                                   buffer
                                  )
         ) == ERR_NONE
        )
       )
    {
        if ((result = pTaggantPutInfo(object,
                                      (ENUMTAGINFO) 0x8003,
                                      (10 * 1024) - 4,
                                      buffer
                                     )
            ) == TNOERR
           )
        {
            result = ERR_BADLIB;
        }
        else if (result == TINSUFFICIENTBUFFER)
        {
            result = ERR_NONE;
        }
    }

    pTaggantObjectFree(object);
    free(buffer);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v255(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test55: add v2 Taggant to 32-bit PE file containing v1 Taggant and full v2 ExtraBlob:");

    if ((result = create_v2_taggant_taggant("v1test01",
                                            "v2test55",
                                            context,
                                            TAGGANT_PEFILE,
                                            licdata,
                                            peobj_len,
                                            FALSE,
                                            TRUE
                                           )
        ) == ERR_NONE
       )
    {
        result = ERR_BADLIB;
    }
    else if (result == TINSUFFICIENTBUFFER)
    {
        result = ERR_NONE;
    }

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v256(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test56: add v2(a) Taggant to 32-bit PE file containing v2(b) Taggant and full v2(a) ExtraBlob:");

    if ((result = create_v2_taggant_taggant("v2test01",
                                            "v2test56",
                                            context,
                                            TAGGANT_PEFILE,
                                            licdata,
                                            peobj_len,
                                            FALSE,
                                            TRUE
                                           )
        ) == ERR_NONE
       )
    {
        result = ERR_BADLIB;
    }
    else if (result == TINSUFFICIENTBUFFER)
    {
        result = ERR_NONE;
    }

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v257(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test57: add v2 Taggant to 64-bit PE file containing v1 Taggant and full v2 ExtraBlob:");

    if ((result = create_v2_taggant_taggant("v1test04",
                                            "v2test57",
                                            context,
                                            TAGGANT_PEFILE,
                                            licdata,
                                            peobj_len,
                                            FALSE,
                                            TRUE
                                           )
        ) == ERR_NONE
       )
    {
        result = ERR_BADLIB;
    }
    else if (result == TINSUFFICIENTBUFFER)
    {
        result = ERR_NONE;
    }

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v258(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test58: add v2(a) Taggant to 64-bit PE file containing v2(b) Taggant and full v2(a) ExtraBlob:");

    if ((result = create_v2_taggant_taggant("v2test05",
                                            "v2test58",
                                            context,
                                            TAGGANT_PEFILE,
                                            licdata,
                                            peobj_len,
                                            FALSE,
                                            TRUE
                                           )
        ) == ERR_NONE
       )
    {
        result = ERR_BADLIB;
    }
    else if (result == TINSUFFICIENTBUFFER)
    {
        result = ERR_NONE;
    }

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v259(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         _In_reads_(jsfile_len) const UNSIGNED8 *jsfile,
                         UNSIGNED64 jsfile_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test59: add v2 Taggant to JS file:");

    result = create_tmp_v2_taggant("v2test59",
                                   context,
                                   TAGGANT_JSFILE,
                                   licdata,
                                   jsfile,
                                   0,
                                   jsfile_len,
                                   FALSE,
                                   FALSE
                                  );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v260(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata
                        )
{
    int result;

    printf(PR_WIDTH, "v2test60: add v2 Taggant to JS file containing v2 Taggant:");

    result = create_v2_taggant_taggant("v2test59",
                                       "v2test60",
                                       context,
                                       TAGGANT_JSFILE,
                                       licdata,
                                       0,
                                       FALSE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v261(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         _In_reads_(pefile_len) const UNSIGNED8 *pefile,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 pefile_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test61: add v2 JS Taggant to 32-bit PE file:");

    result = create_tmp_v2_taggant("v2test61",
                                   context,
                                   TAGGANT_JSFILE,
                                   licdata,
                                   pefile,
                                   peobj_len,
                                   pefile_len,
                                   FALSE,
                                   FALSE
                                  );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v262(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata
                        )
{
    int result;

    printf(PR_WIDTH, "v2test62: add v2 PE Taggant to 32-bit PE file containing v2 JS Taggant:");

    result = create_v2_taggant_taggant("v2test61",
                                       "v2test62",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       0,
                                       FALSE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v263(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         _In_reads_(jsfile_len) const UNSIGNED8 *jsfile,
                         UNSIGNED64 jsfile_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test63: add v2 PE Taggant to JS file:");

    if ((result = create_tmp_v2_taggant("v2test63",
                                        context,
                                        TAGGANT_PEFILE,
                                        licdata,
                                        jsfile,
                                        0,
                                        jsfile_len,
                                        FALSE,
                                        FALSE
                                       )
        ) == ERR_NONE
       )
    {
        result = ERR_BADLIB;
    }
    else if (result == TINVALIDPEFILE)
    {
        result = ERR_NONE;
    }

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v264(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         _In_reads_(pefile_len) const UNSIGNED8 *pefile,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 pefile_len
                        )
{
    int result;

    printf(PR_WIDTH, "v2test64: add v2 JS Taggant to 64-bit PE file:");

    result = create_tmp_v2_taggant("v2test64",
                                   context,
                                   TAGGANT_JSFILE,
                                   licdata,
                                   pefile,
                                   peobj_len,
                                   pefile_len,
                                   FALSE,
                                   FALSE
                                  );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v265(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata
                        )
{
    int result;

    printf(PR_WIDTH, "v2test65: add v2 PE Taggant to 64-bit PE file containing v2 JS Taggant:");

    result = create_v2_taggant_taggant("v2test64",
                                       "v2test65",
                                       context,
                                       TAGGANT_PEFILE,
                                       licdata,
                                       0,
                                       FALSE,
                                       FALSE
                                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v301(_In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         _In_z_ const char *jsonfilename
                        )
{
    int result;

    printf(PR_WIDTH, "v3test01: create v3 Taggant:");

    result = create_v3_taggant(jsonfilename,
                               "v3test01",
                               context,
                               licdata,
                               FALSE,
                               FALSE
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v302(_In_z_ const char *jsonfilename,
                         _In_z_ const char *certfilename,
                         _In_z_ const char *certpwd,
                         _In_reads_(pefile_len) const UNSIGNED8 *pefile,
                         UNSIGNED64 pefile_len
                        )
{
    int result;

    printf(PR_WIDTH, "v3test02: add v3 Taggant to 32-bit PE file:");

    result = create_tmp_v3_taggant("v3test02",
                                   jsonfilename,
                                   "v3test01",
                                   certfilename,
                                   certpwd,
                                   pefile,
                                   pefile_len
                                  );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_v303(_In_z_ const char *jsonfilename,
                         _In_z_ const char *certfilename,
                         _In_z_ const char *certpwd,
                         _In_reads_(pefile_len) const UNSIGNED8 *pefile,
                         UNSIGNED64 pefile_len
                        )
{
    int result;

    printf(PR_WIDTH, "v3test03: add v3 Taggant to 64-bit PE file:");

    result = create_tmp_v3_taggant("v3test03",
                                   jsonfilename,
                                   "v3test01",
                                   certfilename,
                                   certpwd,
                                   pefile,
                                   pefile_len
                                  );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_ds01(void)
{
    int result;

    printf(PR_WIDTH, "vdstest01: add DS to 32-bit PE file containing v1 Taggant:");

    result = create_ds("v1test01",
                       "vdstest01",
                       FALSE
                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_ds02(void)
{
    int result;

    printf(PR_WIDTH, "vdstest02: add DS to 32-bit PE file containing v2 Taggant:");

    result = create_ds("v2test01",
                       "vdstest02",
                       FALSE
                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_ds03(void)
{
    int result;

    printf(PR_WIDTH, "vdstest03: add DS to 32-bit PE file containing good v2 Taggant and good v1 Taggant:");

    result = create_ds("v2test02",
                       "vdstest03",
                       FALSE
                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_ds04(void)
{
    int result;

    printf(PR_WIDTH, "vdstest04: add DS to 32-bit PE file containing good v2(a) Taggant and good v2(b) Taggant:");

    result = create_ds("v2test03",
                       "vdstest04",
                       FALSE
                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_ds05(void)
{
    int result;

    printf(PR_WIDTH, "vdstest05: add DS to 32-bit PE file containing good v2(a) Taggant and good v2(b) Taggant and good v1 Taggant:");

    result = create_ds("v2test04",
                       "vdstest05",
                       FALSE
                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_ds06(void)
{
    int result;
    
    printf(PR_WIDTH, "vdstest06: add DS to 64-bit PE file containing v1 Taggant:");

    result = create_ds("v1test04",
                       "vdstest06",
                       TRUE
                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_ds07(void)
{
    int result;

    printf(PR_WIDTH, "vdstest07: add DS to 64-bit PE file containing v2 Taggant:");

    result = create_ds("v2test32",
                       "vdstest07",
                       TRUE
                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_ds08(void)
{
    int result;

    printf(PR_WIDTH, "vdstest08: add DS to 64-bit PE file containing good v2 Taggant and good v1 Taggant:");

    result = create_ds("v2test06",
                       "vdstest08",
                       TRUE
                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_ds09(void)
{
    int result;

    printf(PR_WIDTH, "vdstest09: add DS to 64-bit PE file containing good v2(a) Taggant and good v2(b) Taggant:");

    result = create_ds("v2test07",
                       "vdstest09",
                       TRUE
                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_ds10(void)
{
    int result;

    printf(PR_WIDTH, "vdstest10: add DS to 64-bit PE file containing good v2(a) Taggant and good v2(b) Taggant and good v1 Taggant:");

    result = create_ds("v2test08",
                       "vdstest10",
                       TRUE
                      );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_eof01(_In_ const PTAGGANTCONTEXT context,
                          _In_z_ const UNSIGNED8 *licdata,
                          _In_ const UNSIGNED8 *pefile,
                          UNSIGNED64 peobj_len,
                          UNSIGNED64 pefile_len
                         )
{
    int result;

    printf(PR_WIDTH, "veoftest01: add v1 Taggant at EOF of 32-bit PE file containing v2 Taggant:");

    result = create_eof("veoftest01",
                        context,
                        licdata,
                        pefile,
                        peobj_len,
                        pefile_len
                       );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_eof02(_In_ const PTAGGANTCONTEXT context,
                          _In_z_ const UNSIGNED8 *licdata,
                          _In_ const UNSIGNED8 *pefile,
                          UNSIGNED64 peobj_len,
                          UNSIGNED64 pefile_len
                         )
{
    int result;

    printf(PR_WIDTH, "veoftest02: add v1 Taggant at EOF of 64-bit PE file containing v2 Taggant:");

    result = create_eof("veoftest02",
                        context,
                        licdata,
                        pefile,
						peobj_len,
						pefile_len
                       );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_spv_pe(_In_ const PTAGGANTCONTEXT context,
                       _In_z_ const UNSIGNED8 *licdata,
                       _In_ const UNSIGNED8 *pefile32,
                       UNSIGNED64 peobj32_len,
                       UNSIGNED64 pefile32_len,
                       UNSIGNED64 tag32_off,
                       UNSIGNED32 tag32_len,
                       _In_ const UNSIGNED8 *pefile64,
                       UNSIGNED64 peobj64_len,
                       UNSIGNED64 pefile64_len,
                       UNSIGNED64 tag64_off,
                       UNSIGNED32 tag64_len,
                       UNSIGNED64 v1file32_len,
                       UNSIGNED64 v1file64_len,
                       int use_default_file_size,
                       _In_z_ const char *jsonfilename,
                       _In_z_ const char *certfilename,
                       _In_z_ const char *certpwd
                      )
{
    int result;

    UNSIGNED64 file32_len = use_default_file_size ? 0 : pefile32_len;
    UNSIGNED64 file64_len = use_default_file_size ? 0 : pefile64_len;

    if (((result = test_spv_v101(context,
                                 licdata,
                                 pefile32,
                                 peobj32_len,
                                 pefile32_len,
                                 v1file32_len,
                                 tag32_off,
                                 tag32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v102(context,
                                 licdata,
                                 peobj32_len,
                                 file32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v103(context,
                                 licdata,
                                 peobj32_len,
                                 tag32_off
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v104(context,
                                 licdata,
                                 pefile64,
                                 peobj64_len,
                                 pefile64_len,
                                 v1file64_len,
                                 tag64_off,
                                 tag64_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v105(context,
                                 licdata,
                                 peobj64_len,
                                 file64_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v106(context,
                                 licdata,
                                 peobj64_len,
                                 tag64_off
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v107(context,
                                 licdata,
                                 peobj32_len,
                                 tag32_off
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v108(context,
                                 licdata,
                                 peobj32_len,
                                 file32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v109(context,
                                 licdata,
                                 peobj32_len,
                                 tag32_off
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v110(context,
                                 licdata,
                                 peobj64_len,
                                 tag64_off
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v111(context,
                                 licdata,
                                 peobj64_len,
                                 file64_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v112(context,
                                 licdata,
                                 peobj64_len,
                                 tag64_off
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v113(context,
                                 licdata
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v114(context,
                                 licdata,
                                 peobj32_len,
                                 tag32_off
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v115(context,
                                 licdata
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v116(context,
                                 licdata,
                                 peobj64_len,
                                 tag64_off
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v117(context,
                                 licdata
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v118(context,
                                 licdata,
                                 peobj32_len,
                                 tag32_off
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v119(context,
                                 licdata
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v120(context,
                                 licdata,
                                 peobj64_len,
                                 tag64_off
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v121(context,
                                 licdata,
                                 pefile32,
                                 peobj32_len,
                                 pefile32_len,
                                 v1file32_len,
                                 tag32_off,
                                 tag32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v122(context,
                                 licdata,
                                 pefile64,
                                 peobj64_len,
                                 pefile64_len,
                                 v1file64_len,
                                 tag64_off,
                                 tag64_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v123(context,
                                 licdata,
                                 pefile32,
                                 peobj32_len,
                                 pefile32_len,
                                 v1file32_len,
                                 tag32_off,
                                 tag32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v124(context,
                                 licdata,
                                 peobj32_len,
                                 tag32_off
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v125(context,
                                 licdata,
                                 pefile64,
                                 peobj64_len,
                                 pefile64_len,
                                 v1file64_len,
                                 tag64_off,
                                 tag64_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v126(context,
                                 licdata,
                                 peobj64_len,
                                 tag64_off
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v127(context,
                                 licdata,
                                 pefile32,
                                 peobj32_len,
                                 pefile32_len,
                                 v1file32_len,
                                 tag32_off,
                                 tag32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v128(context,
                                 licdata,
                                 peobj32_len,
                                 file32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v129(context,
                                 licdata,
                                 pefile32,
                                 peobj32_len,
                                 pefile32_len,
                                 tag32_off,
                                 tag32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v130(context,
                                 licdata,
                                 pefile64,
                                 peobj64_len,
                                 pefile64_len,
                                 v1file64_len,
                                 tag64_off,
                                 tag64_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v131(context,
                                 licdata,
                                 peobj64_len,
                                 pefile64_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v132(context,
                                 licdata,
                                 pefile64,
                                 peobj64_len,
                                 pefile64_len,
                                 tag64_off,
                                 tag64_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v133()
         ) != ERR_NONE
        )
     || ((result = test_spv_v134()
         ) != ERR_NONE
        )
     || ((result = test_spv_v201(context,
                                 licdata,
                                 pefile32,
                                 peobj32_len,
                                 pefile32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v202(context,
                                 licdata,
                                 peobj32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v203(context,
                                 licdata,
                                 peobj32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v204(context,
                                 licdata,
                                 peobj32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v205(context,
                                 licdata,
                                 pefile64,
                                 peobj64_len,
                                 pefile64_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v206(context,
                                 licdata,
                                 peobj64_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v207(context,
                                 licdata,
                                 peobj64_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v208(context,
                                 licdata,
                                 peobj64_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v209(context,
                                 licdata,
                                 pefile32,
                                 peobj32_len,
                                 pefile32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v210(context,
                                 licdata,
                                 peobj32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v211(context,
                                 licdata,
                                 peobj32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v212(context,
                                 licdata,
                                 peobj32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v213(context,
                                 licdata,
                                 pefile64,
                                 peobj64_len,
                                 pefile64_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v214(context,
                                 licdata,
                                 peobj64_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v215(context,
                                 licdata,
                                 peobj64_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v216(context,
                                 licdata,
                                 peobj64_len
                                )
         ) != ERR_NONE
        )
#if defined(CSA_MODE)
     || ((result = test_spv_v217(context,
                                 licdata,
                                 peobj32_len
                                )
         ) != ERR_NONE
        )
#endif
     || ((result = test_spv_v218(context,
                                 licdata,
                                 peobj32_len
                                )
         ) != ERR_NONE
        )
#if defined(CSA_MODE)
     || ((result = test_spv_v219(context,
                                 licdata,
                                 peobj64_len
                                )
         ) != ERR_NONE
        )
#endif
     || ((result = test_spv_v220(context,
                                 licdata,
                                 peobj64_len
                                )
         ) != ERR_NONE
        )
#if defined(CSA_MODE)
     || ((result = test_spv_v221(context,
                                 licdata,
                                 peobj32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v222(context,
                                 licdata,
                                 peobj32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v223(context,
                                 licdata,
                                 peobj64_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v224(context,
                                 licdata,
                                 peobj64_len
                                )
         ) != ERR_NONE
        )
#endif
     || ((result = test_spv_v225(context,
                                 licdata,
                                 pefile32,
                                 peobj32_len,
                                 pefile32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v226(context,
                                 licdata,
                                 peobj32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v227(context,
                                 licdata,
                                 peobj32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v228(context,
                                 licdata,
                                 peobj32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v229(context,
                                 licdata,
                                 pefile64,
                                 peobj64_len,
                                 pefile64_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v230(context,
                                 licdata,
                                 peobj64_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v231(context,
                                 licdata,
                                 peobj64_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v232(context,
                                 licdata,
                                 peobj64_len
                                )
         ) != ERR_NONE
        )
#if defined(CSA_MODE)
     || ((result = test_spv_v233(context,
                                 licdata,
                                 peobj32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v234(context,
                                 licdata,
                                 peobj32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v235(context,
                                 licdata,
                                 peobj64_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v236(context,
                                 licdata,
                                 peobj64_len
                                )
         ) != ERR_NONE
        )
#endif
     || ((result = test_spv_v237(context,
                                 licdata,
                                 pefile32,
                                 peobj32_len,
                                 pefile32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v238(context,
                                 licdata,
                                 peobj32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v239(context,
                                 licdata,
                                 peobj32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v240(context,
                                 licdata,
                                 peobj32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v241(context,
                                 licdata,
                                 peobj32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v242(context,
                                 licdata,
                                 peobj32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v243(context,
                                 licdata,
                                 peobj32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v244(context,
                                 licdata,
                                 pefile64,
                                 peobj64_len,
                                 pefile64_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v245(context,
                                 licdata,
                                 peobj64_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v246(context,
                                 licdata,
                                 peobj64_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v247(context,
                                 licdata,
                                 peobj64_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v248(context,
                                 licdata,
                                 peobj64_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v249(context,
                                 licdata,
                                 peobj64_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v250(context,
                                 licdata,
                                 peobj64_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v251(licdata,
                                 pefile32,
                                 pefile32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v252(licdata,
                                 pefile32,
                                 pefile32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v253()
         ) != ERR_NONE
        )
     || ((result = test_spv_v254()
         ) != ERR_NONE
        )
     || ((result = test_spv_v255(context,
                                 licdata,
                                 peobj32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v256(context,
                                 licdata,
                                 peobj32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v257(context,
                                 licdata,
                                 peobj64_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v258(context,
                                 licdata,
                                 peobj64_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v261(context,
                                 licdata,
                                 pefile32,
                                 peobj32_len,
                                 pefile32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v262(context,
                                 licdata
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v264(context,
                                 licdata,
                                 pefile64,
                                 peobj64_len,
                                 pefile64_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v265(context,
                                 licdata
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v301(context,
                                 licdata,
                                 jsonfilename
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v302(jsonfilename,
                                 certfilename,
                                 certpwd,
                                 pefile32,
                                 pefile32_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v303(jsonfilename,
                                 certfilename,
                                 certpwd,
                                 pefile64,
                                 pefile64_len
                                )
         ) != ERR_NONE
        )
       )
    {
        printf("fail\n");
    }

    return result;
}

static int test_spv_js(_In_ const PTAGGANTCONTEXT context,
                       _In_z_ const UNSIGNED8 *licdata,
                       _In_reads_(jsfile_len) const UNSIGNED8 *jsfile,
                       UNSIGNED64 jsfile_len
                      )
{
    int result;

    if (((result = test_spv_v134()) != ERR_NONE)
     || ((result = test_spv_v259(context,
                                 licdata,
                                 jsfile,
                                 jsfile_len
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v260(context,
                                 licdata
                                )
         ) != ERR_NONE
        )
     || ((result = test_spv_v263(context,
                                 licdata,
                                 jsfile,
                                 jsfile_len
                                )
         ) != ERR_NONE
        )
       )
    {
        printf("fail\n");
    }

    return result;
}

static int test_spv_ds(void)
{
    int result;

    if (((result = test_spv_ds01()) != ERR_NONE)
     || ((result = test_spv_ds02()) != ERR_NONE)
     || ((result = test_spv_ds03()) != ERR_NONE)
     || ((result = test_spv_ds04()) != ERR_NONE)
     || ((result = test_spv_ds05()) != ERR_NONE)
     || ((result = test_spv_ds06()) != ERR_NONE)
     || ((result = test_spv_ds07()) != ERR_NONE)
     || ((result = test_spv_ds08()) != ERR_NONE)
     || ((result = test_spv_ds09()) != ERR_NONE)
     || ((result = test_spv_ds10()) != ERR_NONE)
       )
    {
        printf("fail\n");
    }

    return result;
}

static int test_spv_eof(_In_ const PTAGGANTCONTEXT context,
                        _In_z_ const UNSIGNED8 *licdata,
                        _In_ const UNSIGNED8 *pefile32,
                        UNSIGNED64 peobj32_len,
                        UNSIGNED64 pefile32_len,
                        _In_ const UNSIGNED8 *pefile64,
                        UNSIGNED64 peobj64_len,
                        UNSIGNED64 pefile64_len
                       )
{
    int result;

    if (((result = test_spv_eof01(context,
                                  licdata,
                                  pefile32,
                                  peobj32_len,
                                  pefile32_len
                                 )
         ) != ERR_NONE
        )
     || ((result = test_spv_eof02(context,
                                  licdata,
                                  pefile64,
                                  peobj64_len,
                                  pefile64_len
                                 )
         ) != ERR_NONE
        )
       )
    {
        printf("fail\n");
    }

    return result;
}

static int test_ssv_001(_In_ const PTAGGANTCONTEXT context)
{
    int result;

    printf(PR_WIDTH, "(001)testing 32-bit PE file containing no Taggant:");

    result = validate_no_taggant("v1test01",
                                 "vssvtest001",
                                 context
                                );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_002(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(002)testing 32-bit PE file containing good v1 Taggant and good image and no overlay:");

    taggant = NULL;
    result = validate_taggant("v1test01",
                              &taggant,
                              context,
                              rootdata,
                              NULL,
                              FALSE,
                              FALSE,
                              TAGGANT_PEFILE,
                              &taglast,
                              &method
                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_003(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(003)testing 32-bit PE file containing good v2 Taggant and good image and no overlay:");

    taggant = NULL;
    result = validate_taggant("v2test01",
                              &taggant,
                              context,
                              rootdata,
                              NULL,
                              FALSE,
                              FALSE,
                              TAGGANT_PEFILE,
                              &taglast,
                              &method
                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_004(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(004)testing 32-bit PE file containing good v2 Taggant and good v1 Taggant and good image and no overlay:");

    taggant = NULL;
    result = validate_taggant_taggant("v2test02",
                                      &taggant,
                                      context,
                                      rootdata,
                                      NULL,
                                      FALSE,
                                      FALSE,
                                      TAGGANT_PEFILE,
                                      &taglast,
                                      &method
                                     );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_005(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(005)testing 32-bit PE file containing good v2 Taggant and good v2 Taggant and good image and no overlay:");

    taggant = NULL;
    result = validate_taggant_taggant("v2test03",
                                      &taggant,
                                      context,
                                      rootdata,
                                      NULL,
                                      FALSE,
                                      FALSE,
                                      TAGGANT_PEFILE,
                                      &taglast,
                                      &method
                                     );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_006(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;

    printf(PR_WIDTH, "(006)testing 32-bit PE file containing good v2(a) Taggant and good v2(b) Taggant and good v1 Taggant and good image and no overlay:");

    taggant = NULL;
    result = validate_taggant_taggant_taggant("v2test04",
                                              &taggant,
                                              context,
                                              rootdata,
                                              NULL,
                                              FALSE,
                                              FALSE,
                                              TAGGANT_PEFILE
                                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_007(_In_ const PTAGGANTCONTEXT context)
{
    int result;

    printf(PR_WIDTH, "(007)testing 64-bit PE file containing no Taggant:");

    result = validate_no_taggant("v1test04",
                                 "vssvtest007",
                                 context
                                );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_008(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(008)testing 64-bit PE file containing good v1 Taggant and good image and no overlay:");

    taggant = NULL;
    result = validate_taggant("v1test04",
                              &taggant,
                              context,
                              rootdata,
                              NULL,
                              FALSE,
                              FALSE,
                              TAGGANT_PEFILE,
                              &taglast,
                              &method
                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_009(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(009)testing 64-bit PE file containing good v2 Taggant and good image and no overlay:");

    taggant = NULL;
    result = validate_taggant("v2test05",
                              &taggant,
                              context,
                              rootdata,
                              NULL,
                              FALSE,
                              FALSE,
                              TAGGANT_PEFILE,
                              &taglast,
                              &method
                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_010(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(010)testing 64-bit PE file containing good v2 Taggant and good v1 Taggant and good image and no overlay:");

    taggant = NULL;
    result = validate_taggant_taggant("v2test06",
                                      &taggant,
                                      context,
                                      rootdata,
                                      NULL,
                                      FALSE,
                                      FALSE,
                                      TAGGANT_PEFILE,
                                      &taglast,
                                      &method
                                     );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_011(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(011)testing 64-bit PE file containing good v2 Taggant and good v2 Taggant and good image and no overlay:");

    taggant = NULL;
    result = validate_taggant_taggant("v2test07",
                                      &taggant,
                                      context,
                                      rootdata,
                                      NULL,
                                      FALSE,
                                      FALSE,
                                      TAGGANT_PEFILE,
                                      &taglast,
                                      &method
                                     );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_012(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;

    printf(PR_WIDTH, "(012)testing 64-bit PE file containing good v2(a) Taggant and good v2(b) Taggant and good v1 Taggant and good image and no overlay:");

    taggant = NULL;
    result = validate_taggant_taggant_taggant("v2test08",
                                              &taggant,
                                              context,
                                              rootdata,
                                              NULL,
                                              FALSE,
                                              FALSE,
                                              TAGGANT_PEFILE
                                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_013(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(013)testing 32-bit PE file containing good v1 Taggant and good image and good overlay:");

    taggant = NULL;
    result = validate_taggant("v1test04",
                              &taggant,
                              context,
                              rootdata,
                              NULL,
                              FALSE,
                              FALSE,
                              TAGGANT_PEFILE,
                              &taglast,
                              &method
                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_014(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(014)testing 32-bit PE file containing good v2 Taggant and good image and good overlay:");

    taggant = NULL;
    result = validate_taggant("v2test09",
                              &taggant,
                              context,
                              rootdata,
                              NULL,
                              FALSE,
                              FALSE,
                              TAGGANT_PEFILE,
                              &taglast,
                              &method
                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_015(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        int invalid_size_in_sections
                       )
{
    int result = ERR_NONE;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(015)testing 32-bit PE file containing good v2 Taggant and good v1 Taggant and good image and good overlay:");

    /* This test is expected to fail for valid files with original size less
       than the size for sections. There is no way to differentiate from
       original file and overlay. */
    if (invalid_size_in_sections)
    {
        printf("not tested because peobj32_len != pefixedobj32_len\n");
    }
    else
    {
        taggant = NULL;
        result = validate_taggant_taggant("v2test10",
                                          &taggant,
                                          context,
                                          rootdata,
                                          NULL,
                                          FALSE,
                                          FALSE,
                                          TAGGANT_PEFILE,
                                          &taglast,
                                          &method
                                         );
        pTaggantFreeTaggant(taggant);

        if (result == ERR_NONE)
        {
            printf("pass\n");
        }
	}

    return result;
}

static int test_ssv_016(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        int invalid_size_in_sections
                       )
{
    int result = ERR_NONE;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(016)not testing 32-bit PE file containing good v2(a) Taggant and good v2(b) Taggant and good image and good overlay");

    /* This test is expected to fail for valid files with original size less
       than the size for sections. There is no way to differentiate from
       original file and overlay. */
    if (invalid_size_in_sections)
    {
        printf("not tested because peobj32_len != pefixedobj32_len\n");
    }
    else
    {
        taggant = NULL;
        result = validate_taggant_taggant("v2test11",
                                          &taggant,
                                          context,
                                          rootdata,
                                          NULL,
                                          FALSE,
                                          FALSE,
                                          TAGGANT_PEFILE,
                                          &taglast,
                                          &method
                                         );
        pTaggantFreeTaggant(taggant);

        if (result == ERR_NONE)
        {
            printf("pass\n");
        }
    }

    return result;
}

static int test_ssv_017(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        int invalid_size_in_sections
                       )
{
    int result = ERR_NONE;
    PTAGGANT taggant;

    printf(PR_WIDTH, "(017)testing 32-bit PE file containing good v2(a) Taggant and good v2(b) Taggant and good v1 Taggant and good image and good overlay:");

    /* This test is expected to fail for valid files with original size less
       than the size for sections. There is no way to differentiate from
       original file and overlay. */
    if (invalid_size_in_sections)
    {
        printf("not tested because peobj32_len != pefixedobj32_len\n");
    }
    else
    {
        taggant = NULL;
        result = validate_taggant_taggant_taggant("v2test12",
                                                  &taggant,
                                                  context,
                                                  rootdata,
                                                  NULL,
                                                  FALSE,
                                                  FALSE,
                                                  TAGGANT_PEFILE
                                                 );
        pTaggantFreeTaggant(taggant);

        if (result == ERR_NONE)
        {
            printf("pass\n");
        }
    }

    return result;
}

static int test_ssv_018(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        int invalid_size_in_sections
                       )
{
    int result = ERR_NONE;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(018)testing 64-bit PE file containing good v1 Taggant and good image and good overlay:");

    /* This test is expected to fail for valid files with original size less
       than the size for sections. There is no way to differentiate from
       original file and overlay. */
    if (invalid_size_in_sections)
    {
        printf("not tested because peobj64_len != pefixedobj64_len\n");
    }
    else
    {
        taggant = NULL;
        result = validate_taggant("v1test10",
                                  &taggant,
                                  context,
                                  rootdata,
                                  NULL,
                                  FALSE,
                                  FALSE,
                                  TAGGANT_PEFILE,
                                  &taglast,
                                  &method
                                 );
        pTaggantFreeTaggant(taggant);

        if (result == ERR_NONE)
        {
            printf("pass\n");
        }
    }

    return result;
}

static int test_ssv_019(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        int invalid_size_in_sections
                       )
{
    int result = ERR_NONE;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(019)testing 64-bit PE file containing good v2 Taggant and good image and good overlay:");

    /* This test is expected to fail for valid files with original size less
       than the size for sections. There is no way to differentiate from
       original file and overlay. */
    if (invalid_size_in_sections)
    {
        printf("not tested because peobj64_len != pefixedobj64_len\n");
    }
    else
    {
        taggant = NULL;
        result = validate_taggant("v2test13",
                                  &taggant,
                                  context,
                                  rootdata,
                                  NULL,
                                  FALSE,
                                  FALSE,
                                  TAGGANT_PEFILE,
                                  &taglast,
                                  &method
                                 );
        pTaggantFreeTaggant(taggant);

        if (result == ERR_NONE)
        {
            printf("pass\n");
        }
    }

    return result;
}

static int test_ssv_020(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        int invalid_size_in_sections
                       )
{
    int result = ERR_NONE;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(020)testing 64-bit PE file containing good v2 Taggant and good v1 Taggant and good image and good overlay:");

    /* This test is expected to fail for valid files with original size less
       than the size for sections. There is no way to differentiate from
       original file and overlay. */
    if (invalid_size_in_sections)
    {
        printf("not tested because peobj64_len != pefixedobj64_len\n");
    }
    else
    {
        taggant = NULL;
        result = validate_taggant_taggant("v2test14",
                                          &taggant,
                                          context,
                                          rootdata,
                                          NULL,
                                          FALSE,
                                          FALSE,
                                          TAGGANT_PEFILE,
                                          &taglast,
                                          &method
                                         );
        pTaggantFreeTaggant(taggant);

        if (result == ERR_NONE)
        {
            printf("pass\n");
        }
    }

    return result;
}

static int test_ssv_021(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        int invalid_size_in_sections
                       )
{
    int result = ERR_NONE;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(021)testing 64-bit PE file containing good v2(a) Taggant and good v2(b) Taggant and good image and good overlay:");

    /* This test is expected to fail for valid files with original size less
       than the size for sections. There is no way to differentiate from
       original file and overlay. */
    if (invalid_size_in_sections)
    {
        printf("not tested because peobj64_len != pefixedobj64_len\n");
    }
    else
    {
        taggant = NULL;
        result = validate_taggant_taggant("v2test15",
                                          &taggant,
                                          context,
                                          rootdata,
                                          NULL,
                                          FALSE,
                                          FALSE,
                                          TAGGANT_PEFILE,
                                          &taglast,
                                          &method
                                         );
        pTaggantFreeTaggant(taggant);

        if (result == ERR_NONE)
        {
            printf("pass\n");
        }
    }

    return result;
}

static int test_ssv_022(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        int invalid_size_in_sections
                       )
{
    int result = ERR_NONE;
    PTAGGANT taggant;

    printf(PR_WIDTH, "(022)testing 64-bit PE file containing good v2(a) Taggant and good v2(b) Taggant and good v1 Taggant and good image and good overlay:");

    /* This test is expected to fail for valid files with original size less
       than the size for sections. There is no way to differentiate from
       original file and overlay. */
    if (invalid_size_in_sections)
    {
        printf("not tested because peobj64_len != pefixedobj64_len\n");
    }
    else
    {
        taggant = NULL;
        result = validate_taggant_taggant_taggant("v2test16",
                                                  &taggant,
                                                  context,
                                                  rootdata,
                                                  NULL,
                                                  FALSE,
                                                  FALSE,
                                                  TAGGANT_PEFILE
                                                 );
        pTaggantFreeTaggant(taggant);

        if (result == ERR_NONE)
        {
            printf("pass\n");
        }
    }

    return result;
}

static int test_ssv_023(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        int invalid_size_in_sections
                       )
{
    int result = ERR_NONE;

    printf(PR_WIDTH, "(023)testing 32-bit PE file containing good v1 Taggant and good image and tampered overlay:");

    /* This test is expected to fail for valid files with original size less
       than the size for sections. There is no way to differentiate from
       original file and overlay. */
    if (invalid_size_in_sections)
    {
        printf("not tested because peobj32_len != pefixedobj32_len\n");
    }
    else
    {
        result = validate_tampered("v1test07",
                                   "vssvtest023",
                                   context,
                                   rootdata,
                                   TAMPER_FILELEN,
                                   TAG_1
                                  );

        if (result == ERR_NONE)
        {
            printf("pass\n");
        }
    }

    return result;
}

static int test_ssv_024(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(024)testing 32-bit PE file containing good v2 Taggant and good image and tampered overlay:");

    result = validate_tampered("v2test09",
                               "vssvtest024",
                               context,
                               rootdata,
                               TAMPER_FILELENM1,
                               TAG_1
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_025(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        int invalid_size_in_sections
                       )
{
    int result = ERR_NONE;

    printf(PR_WIDTH, "(025)testing 32-bit PE file containing good v2 Taggant and good v1 Taggant and good image and tampered overlay:");

    /* This test is expected to fail for valid files with original size less
       than the size for sections. There is no way to differentiate from
       original file and overlay. */
    if (invalid_size_in_sections)
    {
        printf("not tested because peobj32_len != pefixedobj32_len\n");
    }
    else
    {
        result = validate_tampered("v2test10",
                                   "vssvtest025",
                                   context,
                                   rootdata,
                                   TAMPER_FILELENM1,
                                   TAG_2
                                  );

        if (result == ERR_NONE)
        {
            printf("pass\n");
        }
    }

    return result;
}

static int test_ssv_026(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(026)testing 32-bit PE file containing good v2(a) Taggant and good v2(b) Taggant and good image and tampered overlay:");

    result = validate_tampered("v2test11",
                               "vssvtest026",
                               context,
                               rootdata,
                               TAMPER_FILELENM2,
                               TAG_2
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_027(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        int invalid_size_in_sections
                       )
{
    int result = ERR_NONE;

    printf(PR_WIDTH, "(027)testing 32-bit PE file containing good v2(a) Taggant and good v2(b) Taggant and good v1 Taggant and good image and tampered overlay:");

    /* This test is expected to fail for valid files with original size less
       than the size for sections. There is no way to differentiate from
       original file and overlay. */
    if (invalid_size_in_sections)
    {
        printf("not tested because peobj32_len != pefixedobj32_len\n");
    }
    else
    {
        result = validate_tampered("v2test12",
                                   "vssvtest027",
                                   context,
                                   rootdata,
                                   TAMPER_FILELENM2,
                                   TAG_3
                                  );

        if (result == ERR_NONE)
        {
            printf("pass\n");
        }
    }

    return result;
}

static int test_ssv_028(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        int invalid_size_in_sections
                       )
{
    int result = ERR_NONE;

    printf(PR_WIDTH, "(028)testing 64-bit PE file containing good v1 Taggant and good image and tampered overlay:");

    /* This test is expected to fail for valid files with original size less
       than the size for sections. There is no way to differentiate from
       original file and overlay. */
    if (invalid_size_in_sections)
    {
        printf("not tested because peobj64_len != pefixedobj64_len\n");
    }
    else
    {
        result = validate_tampered("v1test10",
                                   "vssvtest028",
                                   context,
                                   rootdata,
                                   TAMPER_FILELEN,
                                   TAG_1
                                  );

        if (result == ERR_NONE)
        {
            printf("pass\n");
        }
    }

    return result;
}

static int test_ssv_029(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(029)testing 64-bit PE file containing good v2 Taggant and good image and tampered overlay:");

    result = validate_tampered("v2test13",
                               "vssvtest029",
                               context,
                               rootdata,
                               TAMPER_FILELENM1,
                               TAG_1
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_030(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        int invalid_size_in_sections
                       )
{
    int result = ERR_NONE;

    printf(PR_WIDTH, "(030)testing 64-bit PE file containing good v2 Taggant and good v1 Taggant and good image and tampered overlay:");

    /* This test is expected to fail for valid files with original size less
       than the size for sections. There is no way to differentiate from
       original file and overlay. */
    if (invalid_size_in_sections)
    {
        printf("not tested because peobj64_len != pefixedobj64_len\n");
    }
    else
    {
        result = validate_tampered("v2test14",
                                   "vssvtest030",
                                   context,
                                   rootdata,
                                   TAMPER_FILELENM1,
                                   TAG_2
                                  );

        if (result == ERR_NONE)
        {
            printf("pass\n");
        }
    }

    return result;
}

static int test_ssv_031(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(031)testing 64-bit PE file containing good v2(a) Taggant and good v2(b) Taggant and good image and tampered overlay:");

    result = validate_tampered("v2test15",
                               "vssvtest031",
                               context,
                               rootdata,
                               TAMPER_FILELENM2,
                               TAG_2
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_032(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        int invalid_size_in_sections
                       )
{
    int result = ERR_NONE;

    printf(PR_WIDTH, "(032)testing 64-bit PE file containing good v2(a) Taggant and good v2(b) Taggant and good v1 Taggant and good image and tampered overlay:");

    /* This test is expected to fail for valid files with original size less
       than the size for sections. There is no way to differentiate from
       original file and overlay. */
    if (invalid_size_in_sections)
    {
        printf("not tested because peobj64_len != pefixedobj64_len\n");
    }
    else
    {
        result = validate_tampered("v2test16",
                                   "vssvtest032",
                                   context,
                                   rootdata,
                                   TAMPER_FILELENM2,
                                   TAG_3
                                  );

        if (result == ERR_NONE)
        {
            printf("pass\n");
        }
    }

    return result;
}

static int test_ssv_033(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(033)testing 32-bit PE file containing tampered v1 Taggant:");

    taggant = NULL;
    result = validate_taggant("v1tampered1_32",
                              &taggant,
                              context,
                              rootdata,
                              NULL,
                              FALSE,
                              FALSE,
                              TAGGANT_PEFILE,
                              &taglast,
                              &method
                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        result = ERR_BADLIB;
    }
    else if (result == TBADKEY)
    {
        result = ERR_NONE;
    }

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_034(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(034)testing 32-bit PE file containing tampered v2 Taggant:");

    taggant = NULL;
    result = validate_taggant("v2tampered1_32",
                              &taggant,
                              context,
                              rootdata,
                              NULL,
                              FALSE,
                              FALSE,
                              TAGGANT_PEFILE,
                              &taglast,
                              &method
                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        result = ERR_BADLIB;
    }
    else if (result == TBADKEY)
    {
        result = ERR_NONE;
    }

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_035(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(035)testing 32-bit PE file containing good v2 Taggant and tampered v1 Taggant:");

    result = validate_tampered("v2test02",
                               "vssvtest035",
                               context,
                               rootdata,
                               TAMPER_TAGP101,
                               TAG_1_HMH
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_036(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(036)testing 32-bit PE file containing good v2 Taggant and tampered v2 Taggant:");

    result = validate_tampered("v2test03",
                               "vssvtest036",
                               context,
                               rootdata,
                               TAMPER_FILELENM2P101,
                               TAG_1_HMH
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_037(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(037)testing 32-bit PE file containing good v2(a) Taggant and good v2(b) Taggant and tampered v1 Taggant:");

    result = validate_tampered("v2test04",
                               "vssvtest037",
                               context,
                               rootdata,
                               TAMPER_TAGP101,
                               TAG_2_HMH
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_038(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(038)testing 64-bit PE file containing tampered v1 Taggant:");

    taggant = NULL;
    result = validate_taggant("v1tampered1_64",
                              &taggant,
                              context,
                              rootdata,
                              NULL,
                              FALSE,
                              FALSE,
                              TAGGANT_PEFILE,
                              &taglast,
                              &method
                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        result = ERR_BADLIB;
    }
    else if (result == TBADKEY)
    {
        result = ERR_NONE;
    }

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_039(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(039)testing 64-bit PE file containing tampered v2 Taggant:");

    taggant = NULL;
    result = validate_taggant("v2tampered1_64",
                              &taggant,
                              context,
                              rootdata,
                              NULL,
                              FALSE,
                              FALSE,
                              TAGGANT_PEFILE,
                              &taglast,
                              &method
                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        result = ERR_BADLIB;
    }
    else if (result == TBADKEY)
    {
        result = ERR_NONE;
    }

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_040(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(040)testing 64-bit PE file containing good v2 Taggant and tampered v1 Taggant:");

    result = validate_tampered("v2test06",
                               "vssvtest040",
                               context,
                               rootdata,
                               TAMPER_TAGP101,
                               TAG_1_HMH
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_041(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(041)testing 64-bit PE file containing good v2 Taggant and tampered v2 Taggant:");

    result = validate_tampered("v2test07",
                               "vssvtest041",
                               context,
                               rootdata,
                               TAMPER_FILELENM2P101,
                               TAG_1_HMH
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_042(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(042)testing 64-bit PE file containing good v2(a) Taggant and good v2(b) Taggant and tampered v1 Taggant:");

    result = validate_tampered("v2test08",
                               "vssvtest042",
                               context,
                               rootdata,
                               TAMPER_TAGP101,
                               TAG_2_HMH
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_043(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(043)testing 32-bit PE file containing good v1 Taggant and good v2 Taggant (v1 at eof) and good image");

    taggant = NULL;

    if ((result = validate_taggant("veoftest01",
                                   &taggant,
                                   context,
                                   rootdata,
                                   NULL,
                                   FALSE,
                                   FALSE,
                                   TAGGANT_PEFILE,
                                   &taglast,
                                   &method
                                  )
        ) == ERR_NONE
       )
    {
        if ((result = validate_taggant("veoftest01",
                                       &taggant,
                                       context,
                                       rootdata,
                                       NULL,
                                       FALSE,
                                       FALSE,
                                       TAGGANT_PEFILE,
                                       &taglast,
                                       &method
                                      )
            ) == ERR_NONE
           )
        {
            result = ERR_BADLIB;
        }
        else if (result == TNOTAGGANTS)
        {
            result = ERR_NONE;
        }
    }

    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_044(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(044)testing 32-bit PE file containing good v1 Taggant and good v2 Taggant (v2 at eof) and good image:");

    taggant = NULL;
    result = validate_taggant("v1test03",
                              &taggant,
                              context,
                              rootdata,
                              NULL,
                              FALSE,
                              FALSE,
                              TAGGANT_PEFILE,
                              &taglast,
                              &method
                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        result = ERR_BADLIB;
    }
    else if (result == TMISMATCH)
    {
        result = ERR_NONE;
    }

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_045(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(045)testing 64-bit PE file containing good v1 Taggant and good v2 Taggant (v1 at eof) and good image");

    taggant = NULL;

    if ((result = validate_taggant("veoftest02",
                                   &taggant,
                                   context,
                                   rootdata,
                                   NULL,
                                   FALSE,
                                   FALSE,
                                   TAGGANT_PEFILE,
                                   &taglast,
                                   &method
                                  )
        ) == ERR_NONE
       )
    {
        if ((result = validate_taggant("veoftest02",
                                       &taggant,
                                       context,
                                       rootdata,
                                       NULL,
                                       FALSE,
                                       FALSE,
                                       TAGGANT_PEFILE,
                                       &taglast,
                                       &method
                                      )
            ) == ERR_NONE
           )
        {
            result = ERR_BADLIB;
        }
        else if (result == TNOTAGGANTS)
        {
            result = ERR_NONE;
        }
    }

    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_046(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(046)testing 64-bit PE file containing good v1 Taggant and good v2 Taggant (v2 at eof) and good image:");

    taggant = NULL;
    result = validate_taggant("v1test06",
                              &taggant,
                              context,
                              rootdata,
                              NULL,
                              FALSE,
                              FALSE,
                              TAGGANT_PEFILE,
                              &taglast,
                              &method
                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        result = ERR_BADLIB;
    }
    else if (result == TMISMATCH)
    {
        result = ERR_NONE;
    }

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_047(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(047)testing 32-bit PE file containing good v1 Taggant and tampered HMH region:");

    result = validate_tampered("v1test21",
                               "vssvtest047",
                               context,
                               rootdata,
                               TAMPER_TIME,
                               TAG_1_HMH
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_048(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(048)testing 32-bit PE file containing good v1 Taggant and tampered non-HMH region:");

    result = validate_tampered("v1test21",
                               "vssvtest048",
                               context,
                               rootdata,
                               TAMPER_3,
                               TAG_1
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_049(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(049)testing 32-bit PE file containing good v2 Taggant and tampered HMH region:");

    result = validate_tampered("v2test25",
                               "vssvtest049",
                               context,
                               rootdata,
                               TAMPER_TIME,
                               TAG_1_HMH
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_050(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(050)testing 32-bit PE file containing good v2 Taggant and tampered non-HMH region:");

    result = validate_tampered("v2test25",
                               "vssvtest050",
                               context,
                               rootdata,
                               TAMPER_3,
                               TAG_1
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_051(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(051)testing 32-bit PE file containing good v2 Taggant and good v1 Taggant and tampered v1 HMH region:");

    result = validate_tampered("v2test26",
                               "vssvtest051",
                               context,
                               rootdata,
                               TAMPER_TIME,
                               TAG_2_HMH
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_052(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(052)testing 32-bit PE file containing good v2 Taggant and good v1 Taggant and tampered non-HMH region:");

    result = validate_tampered("v2test26",
                               "vssvtest052",
                               context,
                               rootdata,
                               TAMPER_3,
                               TAG_2
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_053(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(053)testing 32-bit PE file containing good v2(a) Taggant and good v2(b) Taggant and tampered v2(b) HMH region:");

    result = validate_tampered("v2test27",
                               "vssvtest053",
                               context,
                               rootdata,
                               TAMPER_TIME,
                               TAG_2_HMH
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_054(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(054)testing 32-bit PE file containing good v2(a) Taggant and good v2(b) Taggant and tampered non-HMH region:");

    result = validate_tampered("v2test27",
                               "vssvtest054",
                               context,
                               rootdata,
                               TAMPER_3,
                               TAG_2
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_055(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(055)testing 32-bit PE file containing good v2(a) Taggant and good v2(b) Taggant and good v1 Taggant and tampered v1 HMH region:");

    result = validate_tampered("v2test28",
                               "vssvtest055",
                               context,
                               rootdata,
                               TAMPER_TIME,
                               TAG_2_1_HMH
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_056(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(056)testing 32-bit PE file containing good v2(a) Taggant and good v2(b) Taggant and good v1 Taggant and tampered non-HMH region:");

    result = validate_tampered("v2test28",
                               "vssvtest056",
                               context,
                               rootdata,
                               TAMPER_3,
                               TAG_3
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

#if defined(CSA_MODE)
static int test_ssv_057(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(057)testing 32-bit PE file containing good v2 Taggant and good v1 Taggant and broken HMH has EIGNOREHMH:");

    result = validate_eignore("v2test33",
                              context,
                              rootdata
                             );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_058(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(058)testing 32-bit PE file containing good v2 Taggant and good v2 Taggant and broken HMH has EIGNOREHMH:");

    result = validate_eignore("v2test34",
                              context,
                              rootdata
                             );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}
#endif

static int test_ssv_059(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(059)testing 64-bit PE file containing good v1 Taggant and tampered HMH region:");

    result = validate_tampered("v1test22",
                               "vssvtest059",
                               context,
                               rootdata,
                               TAMPER_TIME,
                               TAG_1_HMH
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_060(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(060)testing 64-bit PE file containing good v1 Taggant and tampered non-HMH region:");

    result = validate_tampered("v1test22",
                               "vssvtest060",
                               context,
                               rootdata,
                               TAMPER_3,
                               TAG_1
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_061(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(061)testing 64-bit PE file containing good v2 Taggant and tampered HMH region:");

    result = validate_tampered("v2test29",
                               "vssvtest061",
                               context,
                               rootdata,
                               TAMPER_TIME,
                               TAG_1_HMH
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_062(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(062)testing 64-bit PE file containing good v2 Taggant and tampered non-HMH region:");

    result = validate_tampered("v2test29",
                               "vssvtest062",
                               context,
                               rootdata,
                               TAMPER_3,
                               TAG_1
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_063(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(063)testing 64-bit PE file containing good v2 Taggant and good v1 Taggant and tampered v1 HMH region:");

    result = validate_tampered("v2test30",
                               "vssvtest063",
                               context,
                               rootdata,
                               TAMPER_TIME,
                               TAG_2_HMH
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_064(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(064)testing 64-bit PE file containing good v2 Taggant and good v1 Taggant and tampered non-HMH region:");

    result = validate_tampered("v2test30",
                               "vssvtest064",
                               context,
                               rootdata,
                               TAMPER_3,
                               TAG_2
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_065(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(065)testing 64-bit PE file containing good v2(a) Taggant and good v2(b) Taggant and tampered v2(b) HMH region:");

    result = validate_tampered("v2test31",
                               "vssvtest065",
                               context,
                               rootdata,
                               TAMPER_TIME,
                               TAG_2_HMH
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_066(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(066)testing 64-bit PE file containing good v2(a) Taggant and good v2(b) Taggant and tampered non-HMH region:");

    result = validate_tampered("v2test31",
                               "vssvtest066",
                               context,
                               rootdata,
                               TAMPER_3,
                               TAG_2
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_067(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(067)testing 64-bit PE file containing good v2(a) Taggant and good v2(b) Taggant and good v1 Taggant and tampered v1 HMH region:");

    result = validate_tampered("v2test32",
                               "vssvtest067",
                               context,
                               rootdata,
                               TAMPER_TIME,
                               TAG_2_1_HMH
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_068(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(068)testing 64-bit PE file containing good v2(a) Taggant and good v2(b) Taggant and good v1 Taggant and tampered non-HMH region:");

    result = validate_tampered("v2test32",
                               "vssvtest068",
                               context,
                               rootdata,
                               TAMPER_3,
                               TAG_3
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

#if defined(CSA_MODE)
static int test_ssv_069(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(069)testing 64-bit PE file containing good v2 Taggant and good v1 Taggant and broken HMH has EIGNOREHMH:");

    result = validate_eignore("v2test35",
                              context,
                              rootdata
                             );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_070(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(070)testing 64-bit PE file containing good v2 Taggant and good v2 Taggant and broken HMH has EIGNOREHMH:");

    result = validate_eignore("v2test36",
                              context,
                              rootdata
                             );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}
#endif

static int test_ssv_071(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(071)testing EIGNOREHMH 32-bit PE file containing good v1 Taggant and tampered image:");

    result = validate_tampered(NULL,
                               "vssvtest047",
                               context,
                               rootdata,
                               TAMPER_NONE,
                               TAG_1_FFH
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_072(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(072)testing EIGNOREHMH 32-bit PE file containing good v2 Taggant and tampered image:");

    result = validate_tampered(NULL,
                               "vssvtest049",
                               context,
                               rootdata,
                               TAMPER_NONE,
                               TAG_1_FFH
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_073(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(073)testing 32-bit PE file containing good v2 Taggant and good v1(EIH) Taggant and tampered v1 image:");

    result = validate_tampered(NULL,
                               "vssvtest051",
                               context,
                               rootdata,
                               TAMPER_NONE,
                               TAG_1_1
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_074(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(074)testing 32-bit PE file containing good v2(EIH) Taggant and good v1 Taggant and tampered v1 image:");

    result = validate_tampered(NULL,
                               "vssvtest051",
                               context,
                               rootdata,
                               TAMPER_NONE,
                               TAG_1_FFH
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_075(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(075)testing 32-bit PE file containing good v2(a) Taggant and good v2(b(EIH)) Taggant and tampered v2(b) image:");

    result = validate_tampered(NULL,
                               "vssvtest053",
                               context,
                               rootdata,
                               TAMPER_NONE,
                               TAG_1_1
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_076(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(076)testing 32-bit PE file containing good v2(a(EIH)) Taggant and good v2(b) Taggant and tampered v2(b) image:");

    result = validate_tampered(NULL,
                               "vssvtest053",
                               context,
                               rootdata,
                               TAMPER_NONE,
                               TAG_1_FFH
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_077(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(077)testing 32-bit PE file containing good v2(a) Taggant and good v2(b) Taggant and good v1(EIH) Taggant and tampered v1 image:");

    result = validate_tampered(NULL,
                               "vssvtest055",
                               context,
                               rootdata,
                               TAMPER_NONE,
                               TAG_2_FFH
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_078(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(078)testing 32-bit PE file containing good v2(a) Taggant and good v2(b(EIH)) Taggant and good v1 Taggant and tampered v1 image:");

    result = validate_tampered(NULL,
                               "vssvtest055",
                               context,
                               rootdata,
                               TAMPER_NONE,
                               TAG_1_1
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_079(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(079)testing 32-bit PE file containing good v2(a(EIH)) Taggant and good v2(b) Taggant and good v1 Taggant and tampered v1 image:");

    result = validate_tampered(NULL,
                               "vssvtest055",
                               context,
                               rootdata,
                               TAMPER_NONE,
                               TAG_1_FFH
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_080(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(080)testing EIGNOREHMH 64-bit PE file containing good v1 Taggant and tampered image:");

    result = validate_tampered(NULL,
                               "vssvtest059",
                               context,
                               rootdata,
                               TAMPER_NONE,
                               TAG_1_FFH
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_081(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(081)testing EIGNOREHMH 64-bit PE file containing good v2 Taggant and tampered image:");

    result = validate_tampered(NULL,
                               "vssvtest061",
                               context,
                               rootdata,
                               TAMPER_NONE,
                               TAG_1_FFH
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_082(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(082)testing 64-bit PE file containing good v2 Taggant and good v1(EIH) Taggant and tampered v1 image:");

    result = validate_tampered(NULL,
                               "vssvtest063",
                               context,
                               rootdata,
                               TAMPER_NONE,
                               TAG_1_1
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_083(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(083)testing 64-bit PE file containing good v2(EIH) Taggant and good v1 Taggant and tampered v1 image:");

    result = validate_tampered(NULL,
                               "vssvtest063",
                               context,
                               rootdata,
                               TAMPER_NONE,
                               TAG_1_FFH
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_084(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(084)testing 64-bit PE file containing good v2(a) Taggant and good v2(b(EIH)) Taggant and tampered v2(b) image:");

    result = validate_tampered(NULL,
                               "vssvtest065",
                               context,
                               rootdata,
                               TAMPER_NONE,
                               TAG_1_1
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_085(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(085)testing 64-bit PE file containing good v2(a(EIH)) Taggant and good v2(b) Taggant and tampered v2(b) image:");

    result = validate_tampered(NULL,
                               "vssvtest065",
                               context,
                               rootdata,
                               TAMPER_NONE,
                               TAG_1_FFH
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_086(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(086)testing 64-bit PE file containing good v2(a) Taggant and good v2(b) Taggant and good v1(EIH) Taggant and tampered v1 image:");

    result = validate_tampered(NULL,
                               "vssvtest067",
                               context,
                               rootdata,
                               TAMPER_NONE,
                               TAG_2_FFH
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_087(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(087)testing 64-bit PE file containing good v2(a) Taggant and good v2(b(EIH)) Taggant and good v1 Taggant and tampered v1 image:");

    result = validate_tampered(NULL,
                               "vssvtest067",
                               context,
                               rootdata,
                               TAMPER_NONE,
                               TAG_1_1
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_088(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(088)testing 64-bit PE file containing good v2(a(EIH)) Taggant and good v2(b) Taggant and good v1 Taggant and tampered v1 image:");

    result = validate_tampered(NULL,
                               "vssvtest067",
                               context,
                               rootdata,
                               TAMPER_NONE,
                               TAG_1_FFH
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_089(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        _In_ const UNSIGNED8 *tsrootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(089)testing 32-bit PE file containing good v1(TS) Taggant:");

    taggant = NULL;
    result = validate_taggant("v1test01",
                              &taggant,
                              context,
                              rootdata,
                              tsrootdata,
                              TRUE,
                              FALSE,
                              TAGGANT_PEFILE,
                              &taglast,
                              &method
                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_090(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        _In_ const UNSIGNED8 *tsrootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(090)testing 32-bit PE file containing bad v1(TS) Taggant:");

    taggant = NULL;
    result = validate_taggant("v1test27",
                              &taggant,
                              context,
                              rootdata,
                              tsrootdata,
                              TRUE,
                              FALSE,
                              TAGGANT_PEFILE,
                              &taglast,
                              &method
                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        result = ERR_BADLIB;
    }
    else if (result == TNOTIME)
    {
        result = ERR_NONE;
    }

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_091(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        _In_ const UNSIGNED8 *tsrootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(091)testing 32-bit PE file containing good v2(TS) Taggant:");

    taggant = NULL;
    result = validate_taggant("v2test01",
                              &taggant,
                              context,
                              rootdata,
                              tsrootdata,
                              TRUE,
                              FALSE,
                              TAGGANT_PEFILE,
                              &taglast,
                              &method
                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_092(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        _In_ const UNSIGNED8 *tsrootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(092)testing 32-bit PE file containing bad v2(TS) Taggant:");

    taggant = NULL;
    result = validate_taggant("v2test37",
                              &taggant,
                              context,
                              rootdata,
                              tsrootdata,
                              TRUE,
                              FALSE,
                              TAGGANT_PEFILE,
                              &taglast,
                              &method
                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        result = ERR_BADLIB;
    }
    else if (result == TNOTIME)
    {
        result = ERR_NONE;
    }

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_093(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        _In_ const UNSIGNED8 *tsrootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(093)testing 32-bit PE file containing good v2(TS) Taggant and good v1(TS):");

    taggant = NULL;
    result = validate_taggant_taggant("v2test02",
                                      &taggant,
                                      context,
                                      rootdata,
                                      tsrootdata,
                                      TRUE,
                                      FALSE,
                                      TAGGANT_PEFILE,
                                      &taglast,
                                      &method
                                     );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_094(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        _In_ const UNSIGNED8 *tsrootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(094)testing 32-bit PE file containing good v2(TS) Taggant and bad v1(TS):");

    taggant = NULL;

    if (((result = validate_taggant("v2test38",
                                    &taggant,
                                    context,
                                    rootdata,
                                    tsrootdata,
                                    TRUE,
                                    FALSE,
                                    TAGGANT_PEFILE,
                                    &taglast,
                                    &method
                                   )
         ) == ERR_NONE
        )
     && ((result = taglast) == ERR_NONE)
       )
    {
        result = validate_taggant("v2test38",
                                  &taggant,
                                  context,
                                  rootdata,
                                  tsrootdata,
                                  TRUE,
                                  FALSE,
                                  TAGGANT_PEFILE,
                                  &taglast,
                                  &method
                                 );

        if (result == ERR_NONE)
        {
            result = ERR_BADLIB;
        }
        else if (result == TNOTIME)
        {
            result = ERR_NONE;
        }
    }

    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_095(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        _In_ const UNSIGNED8 *tsrootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(095)testing 32-bit PE file containing bad v2(TS) Taggant and good v1(TS) Taggant:");

    taggant = NULL;
    result = validate_taggant("v2test41",
                              &taggant,
                              context,
                              rootdata,
                              tsrootdata,
                              TRUE,
                              FALSE,
                              TAGGANT_PEFILE,
                              &taglast,
                              &method
                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        result = ERR_BADLIB;
    }
    else if (result == TNOTIME)
    {
        result = ERR_NONE;
    }

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_096(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        _In_ const UNSIGNED8 *tsrootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(096)testing 32-bit PE file containing good v2(a(TS)) Taggant and good v2(b(TS)) Taggant:");

    taggant = NULL;
    result = validate_taggant_taggant("v2test03",
                                      &taggant,
                                      context,
                                      rootdata,
                                      tsrootdata,
                                      TRUE,
                                      FALSE,
                                      TAGGANT_PEFILE,
                                      &taglast,
                                      &method
                                     );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_097(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        _In_ const UNSIGNED8 *tsrootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(097)testing 32-bit PE file containing good v2(a(TS)) Taggant and bad v2(b(TS)) Taggant:");

    taggant = NULL;

    if (((result = validate_taggant("v2test39",
                                    &taggant,
                                    context,
                                    rootdata,
                                    tsrootdata,
                                    TRUE,
                                    FALSE,
                                    TAGGANT_PEFILE,
                                    &taglast,
                                    &method
                                   )
         ) == ERR_NONE
        )
     && ((result = taglast) == ERR_NONE)
       )
    {
        result = validate_taggant("v2test39",
                                  &taggant,
                                  context,
                                  rootdata,
                                  tsrootdata,
                                  TRUE,
                                  FALSE,
                                  TAGGANT_PEFILE,
                                  &taglast,
                                  &method
                                 );

        if (result == ERR_NONE)
        {
            result = ERR_BADLIB;
        }
        else if (result == TNOTIME)
        {
            result = ERR_NONE;
        }
    }

    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_098(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        _In_ const UNSIGNED8 *tsrootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(098)testing 32-bit PE file containing bad v2(a(TS)) Taggant and good v2(b(TS)) Taggant:");

    taggant = NULL;
    result = validate_taggant("v2test42",
                              &taggant,
                              context,
                              rootdata,
                              tsrootdata,
                              TRUE,
                              FALSE,
                              TAGGANT_PEFILE,
                              &taglast,
                              &method
                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        result = ERR_BADLIB;
    }
    else if (result == TNOTIME)
    {
        result = ERR_NONE;
    }

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_099(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        _In_ const UNSIGNED8 *tsrootdata
                       )
{
    int result;
    PTAGGANT taggant;

    printf(PR_WIDTH, "(099)testing 32-bit PE file containing good v2(a(TS)) Taggant and good v2(b(TS)) Taggant and good v1(TS) Taggant:");

    taggant = NULL;
    result = validate_taggant_taggant_taggant("v2test04",
                                              &taggant,
                                              context,
                                              rootdata,
                                              tsrootdata,
                                              TRUE,
                                              FALSE,
                                              TAGGANT_PEFILE
                                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_100(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        _In_ const UNSIGNED8 *tsrootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(100)testing 32-bit PE file containing good v2(a(TS)) Taggant and good v2(b(TS)) Taggant and bad v1(TS) Taggant:");

    taggant = NULL;

    if (((result = validate_taggant_taggant("v2test40",
                                            &taggant,
                                            context,
                                            rootdata,
                                            tsrootdata,
                                            TRUE,
                                            FALSE,
                                            TAGGANT_PEFILE,
                                            &taglast,
                                            &method
                                           )
         ) == ERR_NONE
        )
     && ((result = taglast) == ERR_NONE)
       )
    {
        result = validate_taggant("v2test40",
                                  &taggant,
                                  context,
                                  rootdata,
                                  tsrootdata,
                                  TRUE,
                                  FALSE,
                                  TAGGANT_PEFILE,
                                  &taglast,
                                  &method
                                 );

        if (result == ERR_NONE)
        {
            result = ERR_BADLIB;
        }
        else if (result == TNOTIME)
        {
            result = ERR_NONE;
        }
    }

    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_101(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        _In_ const UNSIGNED8 *tsrootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(101)testing 32-bit PE file containing good v2(a(TS)) Taggant and bad v2(b(TS)) Taggant and good v1(TS) Taggant:");

    taggant = NULL;

    if (((result = validate_taggant("v2test43",
                                    &taggant,
                                    context,
                                    rootdata,
                                    tsrootdata,
                                    TRUE,
                                    FALSE,
                                    TAGGANT_PEFILE,
                                    &taglast,
                                    &method
                                   )
         ) == ERR_NONE
        )
     && ((result = taglast) == ERR_NONE)
       )
    {
        result = validate_taggant("v2test43",
                                  &taggant,
                                  context,
                                  rootdata,
                                  tsrootdata,
                                  TRUE,
                                  FALSE,
                                  TAGGANT_PEFILE,
                                  &taglast,
                                  &method
                                 );

        if (result == ERR_NONE)
        {
            result = ERR_BADLIB;
        }
        else if (result == TNOTIME)
        {
            result = ERR_NONE;
        }
    }

    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_102(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        _In_ const UNSIGNED8 *tsrootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(102)testing 64-bit PE file containing good v1(TS) Taggant:");

    taggant = NULL;
    result = validate_taggant("v1test04",
                              &taggant,
                              context,
                              rootdata,
                              tsrootdata,
                              TRUE,
                              FALSE,
                              TAGGANT_PEFILE,
                              &taglast,
                              &method
                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_103(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        _In_ const UNSIGNED8 *tsrootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(103)testing 64-bit PE file containing bad v1(TS) Taggant:");

    taggant = NULL;
    result = validate_taggant("v1test30",
                              &taggant,
                              context,
                              rootdata,
                              tsrootdata,
                              TRUE,
                              FALSE,
                              TAGGANT_PEFILE,
                              &taglast,
                              &method
                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        result = ERR_BADLIB;
    }
    else if (result == TNOTIME)
    {
        result = ERR_NONE;
    }

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_104(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        _In_ const UNSIGNED8 *tsrootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(104)testing 64-bit PE file containing good v2(TS) Taggant:");

    taggant = NULL;
    result = validate_taggant("v2test05",
                              &taggant,
                              context,
                              rootdata,
                              tsrootdata,
                              TRUE,
                              FALSE,
                              TAGGANT_PEFILE,
                              &taglast,
                              &method
                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_105(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        _In_ const UNSIGNED8 *tsrootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(105)testing 64-bit PE file containing bad v2(TS) Taggant:");

    taggant = NULL;
    result = validate_taggant("v2test44",
                              &taggant,
                              context,
                              rootdata,
                              tsrootdata,
                              TRUE,
                              FALSE,
                              TAGGANT_PEFILE,
                              &taglast,
                              &method
                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        result = ERR_BADLIB;
    }
    else if (result == TNOTIME)
    {
        result = ERR_NONE;
    }

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_106(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        _In_ const UNSIGNED8 *tsrootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(106)testing 64-bit PE file containing good v2(TS) Taggant and good v1(TS):");

    taggant = NULL;
    result = validate_taggant_taggant("v2test06",
                                      &taggant,
                                      context,
                                      rootdata,
                                      tsrootdata,
                                      TRUE,
                                      FALSE,
                                      TAGGANT_PEFILE,
                                      &taglast,
                                      &method
                                     );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_107(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        _In_ const UNSIGNED8 *tsrootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(107)testing 64-bit PE file containing good v2(TS) Taggant and bad v1(TS):");

    taggant = NULL;

    if (((result = validate_taggant("v2test45",
                                    &taggant,
                                    context,
                                    rootdata,
                                    tsrootdata,
                                    TRUE,
                                    FALSE,
                                    TAGGANT_PEFILE,
                                    &taglast,
                                    &method
                                   )
         ) == ERR_NONE
        )
     && ((result = taglast) == ERR_NONE)
       )
    {
        result = validate_taggant("v2test45",
                                  &taggant,
                                  context,
                                  rootdata,
                                  tsrootdata,
                                  TRUE,
                                  FALSE,
                                  TAGGANT_PEFILE,
                                  &taglast,
                                  &method
                                 );

        if (result == ERR_NONE)
        {
            result = ERR_BADLIB;
        }
        else if (result == TNOTIME)
        {
            result = ERR_NONE;
        }
    }

    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_108(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        _In_ const UNSIGNED8 *tsrootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(108)testing 64-bit PE file containing bad v2(TS) Taggant and good v1(TS) Taggant:");

    taggant = NULL;
    result = validate_taggant("v2test48",
                              &taggant,
                              context,
                              rootdata,
                              tsrootdata,
                              TRUE,
                              FALSE,
                              TAGGANT_PEFILE,
                              &taglast,
                              &method
                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        result = ERR_BADLIB;
    }
    else if (result == TNOTIME)
    {
        result = ERR_NONE;
    }

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_109(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        _In_ const UNSIGNED8 *tsrootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(109)testing 64-bit PE file containing good v2(a(TS)) Taggant and good v2(b(TS)) Taggant:");

    taggant = NULL;
    result = validate_taggant_taggant("v2test07",
                                      &taggant,
                                      context,
                                      rootdata,
                                      tsrootdata,
                                      TRUE,
                                      FALSE,
                                      TAGGANT_PEFILE,
                                      &taglast,
                                      &method
                                     );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_110(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        _In_ const UNSIGNED8 *tsrootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(110)testing 32-bit PE file containing good v2(a(TS)) Taggant and bad v2(b(TS)) Taggant:");

    taggant = NULL;

    if (((result = validate_taggant("v2test46",
                                    &taggant,
                                    context,
                                    rootdata,
                                    tsrootdata,
                                    TRUE,
                                    FALSE,
                                    TAGGANT_PEFILE,
                                    &taglast,
                                    &method
                                   )
         ) == ERR_NONE
        )
     && ((result = taglast) == ERR_NONE)
       )
    {
        result = validate_taggant("v2test46",
                                  &taggant,
                                  context,
                                  rootdata,
                                  tsrootdata,
                                  TRUE,
                                  FALSE,
                                  TAGGANT_PEFILE,
                                  &taglast,
                                  &method
                                 );

        if (result == ERR_NONE)
        {
            result = ERR_BADLIB;
        }
        else if (result == TNOTIME)
        {
            result = ERR_NONE;
        }
    }

    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_111(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        _In_ const UNSIGNED8 *tsrootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(111)testing 64-bit PE file containing bad v2(a(TS)) Taggant and good v2(b(TS)) Taggant:");

    taggant = NULL;
    result = validate_taggant("v2test49",
                              &taggant,
                              context,
                              rootdata,
                              tsrootdata,
                              TRUE,
                              FALSE,
                              TAGGANT_PEFILE,
                              &taglast,
                              &method
                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        result = ERR_BADLIB;
    }
    else if (result == TNOTIME)
    {
        result = ERR_NONE;
    }

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_112(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        _In_ const UNSIGNED8 *tsrootdata
                       )
{
    int result;
    PTAGGANT taggant;

    printf(PR_WIDTH, "(112)testing 64-bit PE file containing good v2(a(TS)) Taggant and good v2(b(TS)) Taggant and good v1(TS) Taggant:");

    taggant = NULL;
    result = validate_taggant_taggant_taggant("v2test08",
                                              &taggant,
                                              context,
                                              rootdata,
                                              tsrootdata,
                                              TRUE,
                                              FALSE,
                                              TAGGANT_PEFILE
                                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_113(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        _In_ const UNSIGNED8 *tsrootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(113)testing 64-bit PE file containing good v2(a(TS)) Taggant and good v2(b(TS)) Taggant and bad v1(TS) Taggant:");

    taggant = NULL;

    if (((result = validate_taggant_taggant("v2test47",
                                            &taggant,
                                            context,
                                            rootdata,
                                            tsrootdata,
                                            TRUE,
                                            FALSE,
                                            TAGGANT_PEFILE,
                                            &taglast,
                                            &method
                                           )
         ) == ERR_NONE
        )
     && ((result = taglast) == ERR_NONE)
       )
    {
        result = validate_taggant("v2test47",
                                  &taggant,
                                  context,
                                  rootdata,
                                  tsrootdata,
                                  TRUE,
                                  FALSE,
                                  TAGGANT_PEFILE,
                                  &taglast,
                                  &method
                                 );

        if (result == ERR_NONE)
        {
            result = ERR_BADLIB;
        }
        else if (result == TNOTIME)
        {
            result = ERR_NONE;
        }
    }

    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_114(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        _In_ const UNSIGNED8 *tsrootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(114)testing 64-bit PE file containing good v2(a(TS)) Taggant and bad v2(b(TS)) Taggant and good v1(TS) Taggant:");

    taggant = NULL;

    if (((result = validate_taggant("v2test50",
                                    &taggant,
                                    context,
                                    rootdata,
                                    tsrootdata,
                                    TRUE,
                                    FALSE,
                                    TAGGANT_PEFILE,
                                    &taglast,
                                    &method
                                   )
         ) == ERR_NONE
        )
     && ((result = taglast) == ERR_NONE)
       )
    {
        result = validate_taggant("v2test50",
                                  &taggant,
                                  context,
                                  rootdata,
                                  tsrootdata,
                                  TRUE,
                                  FALSE,
                                  TAGGANT_PEFILE,
                                  &taglast,
                                  &method
                                 );

        if (result == ERR_NONE)
        {
            result = ERR_BADLIB;
        }
        else if (result == TNOTIME)
        {
            result = ERR_NONE;
        }
    }

    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_115(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        UNSIGNED32 tag_len
                       )
{
    int result;

    printf(PR_WIDTH, "(115)testing 32-bit PE file containing good v1 Taggant and unexpected appended data:");

    result = ERR_NONE;

    if (tag_len)
    {
        result = validate_appended("v1test01",
                                   "vssvtest115",
                                   context,
                                   rootdata,
                                   TAGGANT_PEFILE,
                                   TMISMATCH
                                  );
    }

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_116(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(116)testing 32-bit PE file containing good v2 Taggant and unexpected appended data:");

    result = validate_appended("v2test01",
                               "vssvtest116",
                               context,
                               rootdata,
                               TAGGANT_PEFILE,
                               TMISMATCH
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_117(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        UNSIGNED32 tag_len
                       )
{
    int result;

    printf(PR_WIDTH, "(117)testing 64-bit PE file containing good v1 Taggant and unexpected appended data:");

    result = ERR_NONE;

    if (tag_len)
    {
        result = validate_appended("v1test04",
                                   "vssvtest117",
                                   context,
                                   rootdata,
                                   TAGGANT_PEFILE,
                                   TMISMATCH
                                  );
    }

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_118(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(118)testing 64-bit PE file containing good v2 Taggant and unexpected appended data:");

    result = validate_appended("v2test05",
                               "vssvtest118",
                               context,
                               rootdata,
                               TAGGANT_PEFILE,
                               TMISMATCH
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_119(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        int invalid_size_in_sections
                       )
{
    int result = ERR_NONE;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(119)testing 32-bit PE file containing good v1 Taggant and digital signature:");

    /* This test is expected to fail for valid files with original size less
       than the size for sections. There is no way to differentiate from
       original file and signature padding. */
    if (invalid_size_in_sections)
    {
        printf("not tested because peobj32_len != pefixedobj32_len\n");
    }
    else
    {
        taggant = NULL;
        result = validate_taggant("vdstest01",
                                  &taggant,
                                  context,
                                  rootdata,
                                  NULL,
                                  FALSE,
                                  FALSE,
                                  TAGGANT_PEFILE,
                                  &taglast,
                                  &method
                                );
        pTaggantFreeTaggant(taggant);

        if (result == ERR_NONE)
        {
            printf("pass\n");
        }
    }

    return result;
}

static int test_ssv_120(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(120)testing 32-bit PE file containing good v2 Taggant and digital signature:");

    taggant = NULL;
    result = validate_taggant("vdstest02",
                              &taggant,
                              context,
                              rootdata,
                              NULL,
                              FALSE,
                              FALSE,
                              TAGGANT_PEFILE,
                              &taglast,
                              &method
                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_121(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(121)testing 32-bit PE file containing good v2 Taggant and good v1 Taggant and digital signature:");

    taggant = NULL;
    result = validate_taggant_taggant("vdstest03",
                                      &taggant,
                                      context,
                                      rootdata,
                                      NULL,
                                      FALSE,
                                      FALSE,
                                      TAGGANT_PEFILE,
                                      &taglast,
                                      &method
                                     );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_122(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(122)testing 32-bit PE file containing good v2(a) Taggant and good v2(b) Taggant and digital signature:");

    taggant = NULL;
    result = validate_taggant_taggant("vdstest04",
                                      &taggant,
                                      context,
                                      rootdata,
                                      NULL,
                                      FALSE,
                                      FALSE,
                                      TAGGANT_PEFILE,
                                      &taglast,
                                      &method
                                     );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_123(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;

    printf(PR_WIDTH, "(123)testing 32-bit PE file containing good v2(a) Taggant and good v2(b) Taggant and good v1 Taggant and digital signature:");

    taggant = NULL;
    result = validate_taggant_taggant_taggant("vdstest05",
                                              &taggant,
                                              context,
                                              rootdata,
                                              NULL,
                                              FALSE,
                                              FALSE,
                                              TAGGANT_PEFILE
                                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_124(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata,
                        int invalid_size_in_sections
                       )
{
    int result = ERR_NONE;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(124)testing 64-bit PE file containing good v1 Taggant and digital signature:");

    /* This test is expected to fail for valid files with original size less
       than the size for sections. There is no way to differentiate from
       original file and signature padding. */
    if (invalid_size_in_sections)
    {
        printf("not tested because peobj64_len != pefixedobj64_len\n");
    }
    else
    {
        taggant = NULL;
        result = validate_taggant("vdstest06",
                                  &taggant,
                                  context,
                                  rootdata,
                                  NULL,
                                  FALSE,
                                  FALSE,
                                  TAGGANT_PEFILE,
                                  &taglast,
                                  &method
                                 );
        pTaggantFreeTaggant(taggant);

        if (result == ERR_NONE)
        {
            printf("pass\n");
        }
    }

    return result;
}

static int test_ssv_125(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(125)testing 64-bit PE file containing good v2 Taggant and digital signature:");

    taggant = NULL;
    result = validate_taggant("vdstest07",
                              &taggant,
                              context,
                              rootdata,
                              NULL,
                              FALSE,
                              FALSE,
                              TAGGANT_PEFILE,
                              &taglast,
                              &method
                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_126(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(126)testing 64-bit PE file containing good v2 Taggant and good v1 Taggant and digital signature:");

    taggant = NULL;
    result = validate_taggant_taggant("vdstest08",
                                      &taggant,
                                      context,
                                      rootdata,
                                      NULL,
                                      FALSE,
                                      FALSE,
                                      TAGGANT_PEFILE,
                                      &taglast,
                                      &method
                                     );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_127(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(127)testing 64-bit PE file containing good v2(a) Taggant and good v2(b) Taggant and digital signature:");

    taggant = NULL;
    result = validate_taggant_taggant("vdstest09",
                                      &taggant,
                                      context,
                                      rootdata,
                                      NULL,
                                      FALSE,
                                      FALSE,
                                      TAGGANT_PEFILE,
                                      &taglast,
                                      &method
                                     );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_128(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;

    printf(PR_WIDTH, "(128)testing 64-bit PE file containing good v2(a) Taggant and good v2(b) Taggant and good v1 Taggant and digital signature:");

    taggant = NULL;
    result = validate_taggant_taggant_taggant("vdstest10",
                                              &taggant,
                                              context,
                                              rootdata,
                                              NULL,
                                              FALSE,
                                              FALSE,
                                              TAGGANT_PEFILE
                                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_129(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(129)testing extracted data from ExtraBlob matches what was added:");

    result = validate_extra("v2test51",
                            context,
                            rootdata
                           );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_130(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(130)testing extracted data from ExtraBlob matches what was added:");

    result = validate_extra("v2test52",
                            context,
                            rootdata
                           );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_131(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(131)testing JS file containing good v2 Taggant and good image:");

    taggant = NULL;
    result = validate_taggant("v2test59",
                              &taggant,
                              context,
                              rootdata,
                              NULL,
                              FALSE,
                              FALSE,
                              TAGGANT_JSFILE,
                              &taglast,
                              &method
                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_132(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(132)testing JS file containing good v2(a) Taggant and good v2(b) Taggant and good image:");

    taggant = NULL;
    result = validate_taggant_taggant("v2test60",
                                      &taggant,
                                      context,
                                      rootdata,
                                      NULL,
                                      FALSE,
                                      FALSE,
                                      TAGGANT_JSFILE,
                                      &taglast,
                                      &method
                                     );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_133(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(133)testing 32-bit PE file containing textual Taggant:");

    taggant = NULL;
    result = validate_taggant("v2test61",
                              &taggant,
                              context,
                              rootdata,
                              NULL,
                              FALSE,
                              FALSE,
                              TAGGANT_JSFILE,
                              &taglast,
                              &method
                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_134(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(134)testing 64-bit PE file containing textual Taggant:");

    taggant = NULL;
    result = validate_taggant("v2test64",
                              &taggant,
                              context,
                              rootdata,
                              NULL,
                              FALSE,
                              FALSE,
                              TAGGANT_JSFILE,
                              &taglast,
                              &method
                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_135(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;

    printf(PR_WIDTH, "(135)testing JS file containing good v2 Taggant and unexpected appended data:");

    result = validate_appended("v2test59",
                               "vssvtest135",
                               context,
                               rootdata,
                               TAGGANT_JSFILE,
                               TNOTAGGANTS
                              );

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_138(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(138)testing 32-bit PE file containing binary v2(a) Taggant and textual (b) Taggant:");

    taggant = NULL;

    if ((result = validate_taggant("v2test62",
                                   &taggant,
                                   context,
                                   rootdata,
                                   NULL,
                                   FALSE,
                                   FALSE,
                                   TAGGANT_PEFILE,
                                   &taglast,
                                   &method
                                  )
        ) == ERR_NONE
       )
    {
        if ((result = validate_taggant("v2test62",
                                       &taggant,
                                       context,
                                       rootdata,
                                       NULL,
                                       FALSE,
                                       FALSE,
                                       TAGGANT_JSFILE,
                                       &taglast,
                                       &method
                                      )
            ) == ERR_NONE
           )
        {
            result = ERR_BADLIB;
        }
		else if (result == TMISMATCH)
        {
            result = ERR_NONE;
        }
    }

    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_139(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(139)testing 64-bit PE file containing binary v2(a) Taggant and textual (b) Taggant:");

    taggant = NULL;

    if ((result = validate_taggant("v2test65",
                                   &taggant,
                                   context,
                                   rootdata,
                                   NULL,
                                   FALSE,
                                   FALSE,
                                   TAGGANT_PEFILE,
                                   &taglast,
                                   &method
                                  )
        ) == ERR_NONE
       )
    {
        if ((result = validate_taggant("v2test65",
                                       &taggant,
                                       context,
                                       rootdata,
                                       NULL,
                                       FALSE,
                                       FALSE,
                                       TAGGANT_JSFILE,
                                       &taglast,
                                       &method
                                      )
            ) == ERR_NONE
           )
        {
            result = ERR_BADLIB;
        }
		else if (result == TMISMATCH)
        {
            result = ERR_NONE;
        }
    }

    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_140(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(140)testing 32-bit PE file containing good v3 Taggant:");

    taggant = NULL;
    result = validate_taggant("v3test02",
                              &taggant,
                              context,
                              rootdata,
                              NULL,
                              FALSE,
                              FALSE,
                              TAGGANT_PESEALFILE,
                              &taglast,
                              &method
                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_141(_In_ const PTAGGANTCONTEXT context,
                        _In_ const UNSIGNED8 *rootdata
                       )
{
    int result;
    PTAGGANT taggant;
    int taglast;
    int method;

    printf(PR_WIDTH, "(140)testing 64-bit PE file containing good v3 Taggant:");

    taggant = NULL;
    result = validate_taggant("v3test03",
                              &taggant,
                              context,
                              rootdata,
                              NULL,
                              FALSE,
                              FALSE,
                              TAGGANT_PESEALFILE,
                              &taglast,
                              &method
                             );
    pTaggantFreeTaggant(taggant);

    if (result == ERR_NONE)
    {
        printf("pass\n");
    }

    return result;
}

static int test_ssv_pe(_In_ const PTAGGANTCONTEXT context,
                       _In_ const UNSIGNED8 *rootdata,
                       _In_ const UNSIGNED8 *tsrootdata,
                       UNSIGNED32 tag32_len,
                       UNSIGNED32 tag64_len,
                       int invalid_size_in_sections32,
                       int invalid_size_in_sections64
                      )
{
    int result;

    if (((result = test_ssv_001(context)) != ERR_NONE)
     || ((result = test_ssv_002(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_003(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_004(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_005(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_006(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_007(context)
         ) != ERR_NONE
        )
     || ((result = test_ssv_008(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_009(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_010(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_011(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_012(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_013(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_014(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_015(context,
                                rootdata,
                                invalid_size_in_sections32
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_016(context,
                                rootdata,
                                invalid_size_in_sections32
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_017(context,
                                rootdata,
                                invalid_size_in_sections32
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_018(context,
                                rootdata,
                                invalid_size_in_sections64
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_019(context,
                                rootdata,
                                invalid_size_in_sections64
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_020(context,
                                rootdata,
                                invalid_size_in_sections64
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_021(context,
                                rootdata,
                                invalid_size_in_sections64
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_022(context,
                                rootdata,
                                invalid_size_in_sections64
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_023(context,
                                rootdata,
                                invalid_size_in_sections32
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_024(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_025(context,
                                rootdata,
                                invalid_size_in_sections32
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_026(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_027(context,
                                rootdata,
                                invalid_size_in_sections32
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_028(context,
                                rootdata,
                                invalid_size_in_sections64
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_029(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_030(context,
                                rootdata,
                                invalid_size_in_sections64
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_031(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_032(context,
                                rootdata,
                                invalid_size_in_sections64
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_033(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_034(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_035(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_036(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_037(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_038(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_039(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_040(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_041(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_042(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_043(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_044(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_045(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_046(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_047(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_048(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_049(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_050(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_051(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_052(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_053(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_054(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_055(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_056(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
#if defined(CSA_MODE)
     || ((result = test_ssv_057(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_058(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
#endif
     || ((result = test_ssv_059(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_060(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_061(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_062(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_063(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_064(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_065(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_066(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_067(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_068(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
#if defined(CSA_MODE)
     || ((result = test_ssv_069(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_070(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
#endif
     || ((result = test_ssv_071(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_072(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_073(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_074(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_075(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_076(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_077(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_078(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_079(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_080(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_081(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_082(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_083(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_084(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_085(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_086(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_087(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_088(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_089(context,
                                rootdata,
                                tsrootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_090(context,
                                rootdata,
                                tsrootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_091(context,
                                rootdata,
                                tsrootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_092(context,
                                rootdata,
                                tsrootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_093(context,
                                rootdata,
                                tsrootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_094(context,
                                rootdata,
                                tsrootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_095(context,
                                rootdata,
                                tsrootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_096(context,
                                rootdata,
                                tsrootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_097(context,
                                rootdata,
                                tsrootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_098(context,
                                rootdata,
                                tsrootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_099(context,
                                rootdata,
                                tsrootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_100(context,
                                rootdata,
                                tsrootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_101(context,
                                rootdata,
                                tsrootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_102(context,
                                rootdata,
                                tsrootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_103(context,
                                rootdata,
                                tsrootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_104(context,
                                rootdata,
                                tsrootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_105(context,
                                rootdata,
                                tsrootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_106(context,
                                rootdata,
                                tsrootdata
                               )
          ) != ERR_NONE
         )
     || ((result = test_ssv_107(context,
                                rootdata,
                                tsrootdata
                               )
          ) != ERR_NONE
         )
     || ((result = test_ssv_108(context,
                                rootdata,
                                tsrootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_109(context,
                                rootdata,
                                tsrootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_110(context,
                                rootdata,
                                tsrootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_111(context,
                                rootdata,
                                tsrootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_112(context,
                                rootdata,
                                tsrootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_113(context,
                                rootdata,
                                tsrootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_114(context,
                                rootdata,
                                tsrootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_115(context,
                                rootdata,
                                tag32_len
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_116(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_117(context,
                                rootdata,
                                tag64_len
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_118(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_119(context,
                                rootdata,
                                invalid_size_in_sections32
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_120(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_121(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_122(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_123(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_124(context,
                                rootdata,
                                invalid_size_in_sections64
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_125(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_126(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_127(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_128(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_129(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_130(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_131(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_132(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_133(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_134(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_135(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_138(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_139(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_140(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_141(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
       )
    {
        printf("fail\n");
    }

    return result;
}

static int test_ssv_js(_In_ const PTAGGANTCONTEXT context,
                       _In_ const UNSIGNED8 *rootdata
                      )
{
    int result;

    if (((result = test_ssv_131(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_132(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
     || ((result = test_ssv_135(context,
                                rootdata
                               )
         ) != ERR_NONE
        )
       )
    {
        printf("fail\n");
    }

    return result;
}

int perform_tests(int argc, char *argv[], int use_default_object_size, int use_default_file_size)
{
    int result;
    const UNSIGNED8 *licdata;
    HMODULE libspv;
    PTAGGANTCONTEXT context;
    HMODULE libssv;
    const UNSIGNED8 *rootdata;
    const UNSIGNED8 *tsrootdata;
    const UNSIGNED8 *aerootdata;

    const UNSIGNED8 *pefile32;
    UNSIGNED64 pefile32_len;
    UNSIGNED64 peobj32_len, pefixedobj32_len;
    UNSIGNED64 tag32_off;
    UNSIGNED32 tag32_len;
    const UNSIGNED8 *pefile64;
    UNSIGNED64 pefile64_len;
    UNSIGNED64 peobj64_len, pefixedobj64_len;
    UNSIGNED64 tag64_off;
    UNSIGNED32 tag64_len;
    const UNSIGNED8 *jsfile;
    UNSIGNED64 jsfile_len;

    printf("checking SPV parameters\n");

    if ((result = validate_spv_parms(argc,
                                     argv,
                                     (UNSIGNED8 **) &licdata,
                                     (UNSIGNED8 **) &pefile32,
                                     &pefile32_len,
                                     &peobj32_len,
                                     &pefixedobj32_len,
                                     &tag32_off,
                                     &tag32_len,
                                     (UNSIGNED8 **) &pefile64,
                                     &pefile64_len,
                                     &peobj64_len,
                                     &pefixedobj64_len,
                                     &tag64_off,
                                     &tag64_len,
                                     (UNSIGNED8 **) &jsfile,
                                     &jsfile_len,
                                     (UNSIGNED8 **) &aerootdata
                                    )
        ) != ERR_NONE
       )
    {
        return result;
    }

    UNSIGNED64 obj32_len = use_default_object_size ? 0 : peobj32_len;
    UNSIGNED64 fixedobj32_len = use_default_object_size ? 0 : pefixedobj32_len;
    UNSIGNED64 obj64_len = use_default_object_size ? 0 : peobj64_len;
    UNSIGNED64 fixedobj64_len = use_default_object_size ? 0 : pefixedobj64_len;

    UNSIGNED64 v1file32_len = tag32_len ? 0 : pefile32_len;
    UNSIGNED64 v1file64_len = tag64_len ? 0 : pefile64_len;

    printf("loading SPV functions\n");

    if ((result = init_spv_library("libspv",
                                   &libspv,
                                   TAGGANT_LIBRARY_VERSION2,
                                   licdata,
                                   aerootdata,
                                   &context
                                  )
        ) != ERR_NONE
       )
    {
        cleanup_spv(TRUE,
                    LVL_FREEDLL,
                    libspv,
                    jsfile,
                    pefile32,
                    pefile64,
                    licdata,
                    0,
                    result
                   );
        return result;
    }

    #if !defined(SKIP_CREATE)
    {
        printf("performing PE creation tests\n");

        if ((result = test_spv_pe(context,
                                  licdata,
                                  pefile32,
                                  fixedobj32_len,
                                  pefile32_len,
                                  tag32_off,
                                  tag32_len,
                                  pefile64,
                                  fixedobj64_len,
                                  pefile64_len,
                                  tag64_off,
                                  tag64_len,
                                  v1file32_len,
                                  v1file64_len,
                                  use_default_file_size,
                                  argv[7],
                                  argv[9],
                                  argv[10]
                                 )
            ) != ERR_NONE
           )
        {
            cleanup_spv(FALSE,
                        LVL_FINALISE,
                        context,
                        libspv,
                        jsfile,
                        pefile64,
                        pefile32,
                        licdata,
                        0,
                        result
                       );
            return result;
        }

        printf("performing JS creation tests\n");

        if ((result = test_spv_js(context,
                                  licdata,
                                  jsfile,
                                  jsfile_len
                                 )
            ) != ERR_NONE
           )
        {
            cleanup_spv(FALSE,
                        LVL_FINALISE,
                        context,
                        libspv,
                        jsfile,
                        pefile64,
                        pefile32,
                        licdata,
                        0,
                        result
                       );
            return result;
        }

        printf("performing DS creation tests\n");

        if ((result = test_spv_ds()) != ERR_NONE)
        {
            cleanup_spv(FALSE,
                        LVL_FINALISE,
                        context,
                        libspv,
                        jsfile,
                        pefile64,
                        pefile32,
                        licdata,
                        0,
                        result
                       );
            return result;
        }

        printf("performing EOF creation tests\n");

        result = test_spv_eof(context,
                              licdata,
                              pefile32,
                              fixedobj32_len,
                              pefile32_len,
                              pefile64,
                              fixedobj64_len,
                              pefile64_len
                             );
        cleanup_spv(!result,
                    LVL_FINALISE,
                    context,
                    libspv,
                    jsfile,
                    pefile64,
                    pefile32,
                    licdata,
                    0,
                    result
                   );

        if (result != ERR_NONE)
        {
            return result;
        }

        printf("completed creation tests\n");
    }
    #endif

    printf("checking SSV parameters\n");

    if ((result = validate_ssv_parms(argv,
                                     (UNSIGNED8 **) &rootdata,
                                     (UNSIGNED8 **) &tsrootdata
                                    )
        ) != ERR_NONE
       )
    {
        #if !defined(KEEP_FILES)
        delete_spv();
        #endif
        return result;
    }

    printf("loading SSV functions\n");

    if ((result = init_ssv_library("libssv",
                                   &libssv,
                                   TAGGANT_LIBRARY_VERSION2,
                                   rootdata,
                                   tsrootdata,
                                   &context
                                  )
        ) != ERR_NONE
       )
    {
        cleanup_ssv(LVL_FREEDLL,
                    libssv,
                    tsrootdata,
                    rootdata,
                    0,
                    result
                   );
        return result;
    }

    printf("performing PE validation tests\n");

    if ((result = test_ssv_pe(context,
                              rootdata,
                              tsrootdata,
                              tag32_len,
                              tag64_len,
                              obj32_len != pefixedobj32_len,
                              obj64_len != pefixedobj64_len
                             )
        ) != ERR_NONE
       )
    {
        cleanup_ssv(LVL_FINALISE,
                    context,
                    libssv,
                    tsrootdata,
                    rootdata,
                    0,
                    result
                   );
        return result;
    }

    if (obj32_len != pefixedobj32_len || obj64_len != pefixedobj64_len)
    {
        printf("\nWarning! Some PE tests were not performed because peobj_len != pefixedobj_len\n\n");
    }

    printf("performing JS validation tests\n");

    result = test_ssv_js(context,
                         rootdata
                        );
    cleanup_ssv(LVL_FINALISE,
                context,
                libssv,
                tsrootdata,
                rootdata,
                0,
                result
               );

    if (result != ERR_NONE)
    {
        return result;
    }

    printf("completed verification tests\n");
    return ERR_NONE;
}

int main(int argc, char *argv[])
{
    int result;

    /* tests with calculated object end and calculated file end */
    result = perform_tests(argc, argv, 0, 0);
    if (result != ERR_NONE)
    {
        return result;
    }

    /* tests with calculated object end and default file end */
    result = perform_tests(argc, argv, 0, 1);
    if (result != ERR_NONE)
    {
        return result;
    }

    /* tests with default object end and calculated file end */
    result = perform_tests(argc, argv, 1, 0);
    if (result != ERR_NONE)
    {
        return result;
    }

    /* tests with default object end and default file end */
    result = perform_tests(argc, argv, 1, 1);
    if (result != ERR_NONE)
    {
        return result;
    }

    printf("completed verification tests\n");
    return ERR_NONE;
}
