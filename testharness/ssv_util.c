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

#include <malloc.h>
#include <stddef.h>
#include "pe_util.h"
#include "file_util.h"
#include "lib_util.h"
#include "err.h"
#include "test.h"
#include "taggantlib.h"
#include "spv_util.h"
#include "ssv_util.h"

extern UNSIGNED32(STDCALL *pTaggantObjectNewEx) (_In_opt_ PTAGGANT pTaggant, UNSIGNED64 uVersion, TAGGANTCONTAINER eTaggantType, _Outptr_ PTAGGANTOBJ *pTaggantObj);
extern PPACKERINFO(STDCALL *pTaggantPackerInfo) (_In_ PTAGGANTOBJ pTaggantObj);
extern UNSIGNED32(STDCALL *pTaggantGetTaggant) (_In_ PTAGGANTCONTEXT pCtx, _In_ PFILEOBJECT hFile, TAGGANTCONTAINER eContainer, _Inout_ PTAGGANT *pTaggant);
extern UNSIGNED32(STDCALL *pTaggantValidateSignature) (_In_ PTAGGANTOBJ pTaggantObj, _In_ PTAGGANT pTaggant, _In_ const PVOID pRootCert);
extern UNSIGNED32(STDCALL *pTaggantGetTimestamp) (_In_ PTAGGANTOBJ pTaggantObj, _Out_writes_(1) UNSIGNED64 *pTime, _In_ const PVOID pTSRootCert);
extern UNSIGNED16(STDCALL *pTaggantGetHashMapDoubles) (_In_ PTAGGANTOBJ pTaggantObj, _Out_writes_(1) PHASHBLOB_HASHMAP_DOUBLE *pDoubles);
extern UNSIGNED32(STDCALL *pTaggantValidateHashMap) (_In_ PTAGGANTCONTEXT pCtx, _In_ PTAGGANTOBJ pTaggantObj, _In_ PFILEOBJECT hFile);
extern UNSIGNED32(STDCALL *pTaggantGetInfo) (_In_ PTAGGANTOBJ pTaggantObj, ENUMTAGINFO eKey, _Inout_updates_(1) UNSIGNED32 *pSize, _Out_writes_opt_(*pSize) PINFO pInfo);
extern UNSIGNED32(STDCALL *pTaggantValidateDefaultHashes) (_In_ PTAGGANTCONTEXT pCtx, _In_ PTAGGANTOBJ pTaggantObj, _In_ PFILEOBJECT hFile, UNSIGNED64 uObjectEnd, UNSIGNED64 uFileEnd);
extern UNSIGNED32(STDCALL *pTaggantFreeTaggant) (_Post_ptr_invalid_ PTAGGANT pTaggant);
extern void (STDCALL *pTaggantObjectFree) (_Post_ptr_invalid_ PTAGGANTOBJ pTaggantObj);

#if !defined(FALSE)
#define FALSE 0
#endif
#if !defined(TRUE)
#define TRUE 1
#endif

#if !defined(BIG_ENDIAN)
#define read_le16(offset) (*((UNSIGNED16 *) (offset)))
#define read_le32(offset) (*((UNSIGNED32 *) (offset)))
#define read_le64(offset) (*((UNSIGNED64 *) (offset)))
#else
#define read_le16(offset) (((unsigned int) *((PINFO) (offset) + 1) << 8) \
                         + *((PINFO) (offset) + 0) \
                          )
#define read_le32(offset) (((UNSIGNED32) *((PINFO) (offset) + 3) << 0x18) \
                         + ((UNSIGNED32) *((PINFO) (offset) + 2) << 0x10) \
                         + ((UNSIGNED32) *((PINFO) (offset) + 1) << 0x08) \
                         + *((PINFO) (offset) + 0) \
                          )
#define read_le64(offset) (((UNSIGNED64) *((PINFO) (offset) + 7) << 0x38) \
                         + ((UNSIGNED64) *((PINFO) (offset) + 6) << 0x30) \
                         + ((UNSIGNED64) *((PINFO) (offset) + 5) << 0x28) \
                         + ((UNSIGNED64) *((PINFO) (offset) + 4) << 0x20) \
                         + ((UNSIGNED64) *((PINFO) (offset) + 3) << 0x18) \
                         + ((UNSIGNED64) *((PINFO) (offset) + 2) << 0x10) \
                         + ((UNSIGNED64) *((PINFO) (offset) + 1) << 0x08) \
                         + *((PINFO) (offset) + 0) \
                          )
#endif

int validate_taggant(_In_ const char *filename,
                     __deref_inout PTAGGANT *ptaggant,
                     _In_ const PTAGGANTCONTEXT context,
                     _In_ const UNSIGNED8 *rootdata,
                     _In_opt_ const UNSIGNED8 *tsrootdata,
                     int gettime,
                     int ignorehmh,
                     TAGGANTCONTAINER tagtype,
                     int *ptaglast,
                     int *pmethod
                    )
{
    int result;
    FILE *infile;
    PTAGGANTOBJ object;
    UNSIGNED64 timest;

    if (gettime
     && !tsrootdata
       )
    {
        return TNOTIME;
    }

    if (fopen_s(&infile,
                filename,
                "rb"
               )
     || !infile
       )
    {
        return ERR_BADOPEN;
    }

    object = NULL;

    if (((result = pTaggantGetTaggant(context,
                                      infile,
                                      tagtype,
                                      ptaggant
                                     )
         ) == TNOERR
        )
     && ((result = pTaggantObjectNewEx(*ptaggant,
                                       0,
                                       (TAGGANTCONTAINER) 0,
                                       &object
                                      )
         ) == TNOERR
        )
     && ((result = pTaggantValidateSignature(object,
                                             *ptaggant,
                                             (PVOID) rootdata
                                            )
         ) == TNOERR
        )
     && (!gettime
      || ((result = pTaggantGetTimestamp(object,
                                         &timest,
                                         (PVOID) tsrootdata
                                        )
          ) == TNOERR
         )
        )
       )
    {
        UNSIGNED8 *tmpfile;
        UNSIGNED64 tmpfile_len;

        if ((result = read_tmp_file(filename,
                                    &tmpfile,
                                    &tmpfile_len
                                   )
            ) == ERR_NONE
           )
        {
            PHASHBLOB_HASHMAP_DOUBLE doubles;
            UNSIGNED32 size;
            char info;
            PPACKERINFO packer_info;

            size = 0;

            if (!ignorehmh
             && ((ignorehmh = !pTaggantGetHashMapDoubles(object,
                                                         &doubles
                                                        )
                 ) == FALSE
                )
               )
            {
                ignorehmh = pTaggantGetInfo(object,
                                            EIGNOREHMH,
                                            &size,
                                            &info
                                           ) == TINSUFFICIENTBUFFER;
            }

            if (!ignorehmh)
            {
                *pmethod = METHOD_HMH;
                result = pTaggantValidateHashMap(context,
                                                 object,
                                                 (PVOID) infile
                                                );
            }
            else
            {
                char file_len[8];
                UNSIGNED64 obj_len, fixedobj_len;
                UNSIGNED64 tag_off;
                UNSIGNED32 tag_len;

                size = 8;
                obj_len = fixedobj_len = 0;

                if (((result = pTaggantGetInfo(object,
                                               EFILEEND,
                                               &size,
                                               file_len
                                              )
                     ) == TNOERR
                    )
                 && ((tagtype != TAGGANT_PEFILE)
                  || ((result = object_sizes(tmpfile,
                                             tmpfile_len,
                                             &obj_len,
                                             &fixedobj_len,
                                             &tag_off,
                                             &tag_len
                                            )
                      ) == ERR_NONE
                     )
                    )
                   )
                {
                    *pmethod = METHOD_FFH;
                    result = pTaggantValidateDefaultHashes(context,
                                                           object,
                                                           (PVOID) infile,
                                                           fixedobj_len,
                                                           read_le64(file_len)
                                                          );
                    /* now try with default sizes */
                    if (result == TNOERR)
                    {
                        result = pTaggantValidateDefaultHashes(context,
                                                               object,
                                                               (PVOID) infile,
                                                               0,
                                                               read_le64(file_len)
                                                              );
                        if (result == TNOERR)
                        {
                            result = pTaggantValidateDefaultHashes(context,
                                                                   object,
                                                                   (PVOID) infile,
                                                                   fixedobj_len,
                                                                   0
                                                                  );
                            if (result == TNOERR)
                            {
                                result = pTaggantValidateDefaultHashes(context,
                                                                       object,
                                                                       (PVOID) infile,
                                                                       0,
                                                                       0
                                                                      );
                            }
                        }
                    }
                }
            }

            if (result == TNOERR)
            {
                size = 1;
                *ptaglast = pTaggantGetInfo(object,
                                            ETAGPREV,
                                            &size,
                                            &info
                                           );
                packer_info = pTaggantPackerInfo(object);
                if (
                    !packer_info ||
                    packer_info->PackerId != PACKER_ID ||
                    packer_info->VersionMajor != PACKER_MAJOR ||
                    packer_info->VersionMinor != PACKER_MINOR ||
                    packer_info->VersionBuild != PACKER_BUILD ||
                    packer_info->Reserved != 0
                    )
                {
                    result = ERR_BADLIB;
                }
            }

            free(tmpfile);
        }
    }

    pTaggantObjectFree(object);
    fclose(infile);
    return result;
}

int validate_taggant_taggant(_In_ const char *filename,
                             __deref_inout PTAGGANT *ptaggant,
                             _In_ const PTAGGANTCONTEXT context,
                             _In_ const UNSIGNED8 *rootdata,
                             _In_opt_ const UNSIGNED8 *tsrootdata,
                             int gettime,
                             int ignorehmh,
                             TAGGANTCONTAINER tagtype,
                             __out_bcount_full(sizeof(int)) int *ptaglast,
                             __out_bcount_full(sizeof(int)) int *pmethod
                            )
{
    int result;

    if (((result = validate_taggant(filename,
                                    ptaggant,
                                    context,
                                    rootdata,
                                    tsrootdata,
                                    gettime,
                                    ignorehmh,
                                    tagtype,
                                    ptaglast,
                                    pmethod
                                   )
         ) == ERR_NONE
        )
     && ((result = *ptaglast) == ERR_NONE)
       )
    {
        if (!ignorehmh
         && (*pmethod != METHOD_HMH)
           )
        {
            result = ERR_BADLIB;
        }
        else
        {
            result = validate_taggant(filename,
                                      ptaggant,
                                      context,
                                      rootdata,
                                      tsrootdata,
                                      gettime,
                                      ignorehmh,
                                      tagtype,
                                      ptaglast,
                                      pmethod
                                     );
        }
    }

    return result;
}

int validate_taggant_taggant_taggant(_In_ const char *filename,
                                     __deref_inout PTAGGANT *ptaggant,
                                     _In_ const PTAGGANTCONTEXT context,
                                     _In_ const UNSIGNED8 *rootdata,
                                     _In_opt_ const UNSIGNED8 *tsrootdata,
                                     int gettime,
                                     int ignorehmh,
                                     TAGGANTCONTAINER tagtype
                                    )
{
    int result;
    int taglast;
    int method;

    if (((result = validate_taggant_taggant(filename,
                                            ptaggant,
                                            context,
                                            rootdata,
                                            tsrootdata,
                                            gettime,
                                            ignorehmh,
                                            tagtype,
                                            &taglast,
                                            &method
                                           )
         ) == ERR_NONE
        )
     && ((result = taglast) == ERR_NONE)
       )
    {
        if (!ignorehmh
         && (method != METHOD_HMH)
           )
        {
            result = ERR_BADLIB;
        }
        else
        {
            result = validate_taggant(filename,
                                      ptaggant,
                                      context,
                                      rootdata,
                                      tsrootdata,
                                      gettime,
                                      ignorehmh,
                                      tagtype,
                                      &taglast,
                                      &method
                                     );
        }
    }

    return result;
}

int validate_no_taggant(_In_z_ const char *filename1,
                        _In_z_ const char *filename2,
                        _In_ const PTAGGANTCONTEXT context
                       )
{
    int result;
    UNSIGNED8 *tmpfile;
    UNSIGNED64 tmpfile_len;
    UNSIGNED32 tag_len;

    if ((result = erase_v1_taggant(filename1,
                                   &tmpfile,
                                   &tmpfile_len,
                                   &tag_len
                                  )
        ) == ERR_NONE
       )
    {
        FILE *infile;

        if ((result = create_tmp_file(filename2,
                                      tmpfile,
                                      tmpfile_len
                                     )
            ) == ERR_NONE
           )
        {
            PTAGGANT taggant;

            if (fopen_s(&infile,
                        filename2,
                        "rb"
                       )
             || !infile
               )
            {
                free(tmpfile);
                return ERR_BADOPEN;
            }

            taggant = NULL;
            result = pTaggantGetTaggant(context,
                                        infile,
                                        TAGGANT_PEFILE,
                                        &taggant
                                       );
            pTaggantFreeTaggant(taggant);
            fclose(infile);

            if (result == TNOERR)
            {
                result = ERR_BADLIB;
            }
            else if (result == TNOTAGGANTS)
            {
                result = ERR_NONE;
            }
        }

        free(tmpfile);
    }

    return result;
}

int validate_tampered(_In_opt_z_ const char *filename1,
                      _In_z_ const char *filename2,
                      _In_ const PTAGGANTCONTEXT context,
                      _In_ const UNSIGNED8 *rootdata,
                      int tamper_lvl,
                      int tag_lvl
                     )
{
    int result;
    UNSIGNED8 *tmpfile;
    UNSIGNED64 tmpfile_len;

    result = ERR_NONE;

    if ((tamper_lvl != TAMPER_NONE)
     && ((result = read_tmp_file(filename1,
                                 &tmpfile,
                                 &tmpfile_len
                                )
         ) == ERR_NONE
        )
       )
    {
        UNSIGNED64 tamper_off;

        switch (tamper_lvl)
        {
            case TAMPER_FILELEN:
            case TAMPER_FILELENM1:
            case TAMPER_FILELENM2:
            {
                tamper_off = tmpfile_len;

                while (--tamper_lvl)
                {
                    tamper_off -= read_le32(tmpfile + tamper_off - (sizeof(TAGGANT_HEADER2) - offsetof(TAGGANT_HEADER2,
                                                                                                       TaggantLength
                                                                                                      )
                                                                   )
                                           );
                }

                break;
            }

            case TAMPER_TAGP101:
            {
                UNSIGNED64 peobj_len, pefixedobj_len;
                UNSIGNED64 tag_off;
                UNSIGNED32 tag_len;

                result = object_sizes(tmpfile,
                                      tmpfile_len,
                                      &peobj_len,
                                      &pefixedobj_len,
                                      &tag_off,
                                      &tag_len
                                     );
                tamper_off = tag_off + 0x101;
                break;
            }

            case TAMPER_FILELENM2P101:
            {
                tamper_off = tmpfile_len - read_le32(tmpfile + tmpfile_len - (sizeof(TAGGANT_HEADER2) - offsetof(TAGGANT_HEADER2,
                                                                                                                 TaggantLength
                                                                                                                )
                                                                             )
                                                    );
                tamper_off -= read_le32(tmpfile + tamper_off - (sizeof(TAGGANT_HEADER2) - offsetof(TAGGANT_HEADER2,
                                                                                                   TaggantLength
                                                                                                  )
                                                               )
                                       ) - 0x101;
                break;
            }

            case TAMPER_TIME:
            {
                tamper_off = read_le32(tmpfile + offsetof(TAG_IMAGE_DOS_HEADER,
                                                          e_lfanew
                                                         )
                                      ) + offsetof(TAG_IMAGE_NT_HEADERS32,
                                                   FileHeader
                                                  ) + offsetof(TAG_IMAGE_FILE_HEADER,
                                                               TimeDateStamp
                                                              ) + 1;
                break;
            }

            case TAMPER_3:
            {
                tamper_off = 3;
                break;
            }

            default:
            {
                tamper_off = 0;
                result = ERR_BADLIB;
            }
        }

        if (result == ERR_NONE)
        {
            ++tmpfile[tamper_off - 1];
            result = create_tmp_file(filename2,
                                     tmpfile,
                                     tmpfile_len
                                    );
        }

        free(tmpfile);
    }

    if (result == ERR_NONE)
    {
        PTAGGANT taggant;
        int taglast;
        int method;

        taggant = NULL;

        switch (tag_lvl)
        {
            case TAG_1:
            {
                result = validate_taggant(filename2,
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
                break;
            }

            case TAG_2:
            {
                result = validate_taggant_taggant(filename2,
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
                break;
            }

            case TAG_3:
            {
                result = validate_taggant_taggant_taggant(filename2,
                                                          &taggant,
                                                          context,
                                                          rootdata,
                                                          NULL,
                                                          FALSE,
                                                          FALSE,
                                                          TAGGANT_PEFILE
                                                         );
                break;
            }

            case TAG_1_HMH:
            case TAG_1_FFH:
            {
                int ignore_hmh;
                int method_cmp;

                ignore_hmh = FALSE;
                method_cmp = METHOD_HMH;

                if (tag_lvl == TAG_1_FFH)
                {
                    ignore_hmh = TRUE;
                    method_cmp = METHOD_FFH;
                }

                if ((result = validate_taggant(filename2,
                                               &taggant,
                                               context,
                                               rootdata,
                                               NULL,
                                               FALSE,
                                               ignore_hmh,
                                               TAGGANT_PEFILE,
                                               &taglast,
                                               &method
                                              )
                    ) == ERR_NONE
                   )
                {
                    result = ERR_BADLIB;
                }
                else if ((method == method_cmp)
                      && (result == TMISMATCH)
                        )
                {
                    result = ERR_NONE;
                }

                break;
            }

            case TAG_2_HMH:
            {
                if ((result = validate_taggant_taggant(filename2,
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
                else if ((method == METHOD_HMH)
                      && (result == TMISMATCH)
                        )
                {
                    result = ERR_NONE;
                }

                break;
            }

            case TAG_2_1_HMH:
            case TAG_2_FFH:
            {
                int ignore_hmh;
                int method_cmp;

                ignore_hmh = FALSE;
                method_cmp = METHOD_HMH;

                if (tag_lvl == TAG_2_FFH)
                {
                    ignore_hmh = TRUE;
                    method_cmp = METHOD_FFH;
                }

                if ((result = validate_taggant_taggant(filename2,
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
                    if (taglast
                     || (method != METHOD_HMH)
                     || ((result = validate_taggant(filename2,
                                                    &taggant,
                                                    context,
                                                    rootdata,
                                                    NULL,
                                                    FALSE,
                                                    ignore_hmh,
                                                    TAGGANT_PEFILE,
                                                    &taglast,
                                                    &method
                                                   )
                         ) == ERR_NONE
                        )
                       )
                    {
                        result = ERR_BADLIB;
                    }
                    else if ((method == method_cmp)
                          && (result == TMISMATCH)
                            )
                    {
                        result = ERR_NONE;
                    }
                }

                break;
            }

            case TAG_1_1:
            {
                if ((result = validate_taggant(filename2,
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
                    if (taglast
                     || (method != METHOD_HMH)
                     || ((result = validate_taggant(filename2,
                                                    &taggant,
                                                    context,
                                                    rootdata,
                                                    NULL,
                                                    FALSE,
                                                    TRUE,
                                                    TAGGANT_PEFILE,
                                                    &taglast,
                                                    &method
                                                   )
                         ) == ERR_NONE
                        )
                       )
                    {
                        result = ERR_BADLIB;
                    }
                    else if ((method == METHOD_FFH)
                          && (result == TMISMATCH)
                            )
                    {
                        result = ERR_NONE;
                    }
                }

                break;
            }

            default:
            {
                result = ERR_BADLIB;
            }
        }

        pTaggantFreeTaggant(taggant);
    }

    return result;
}

#if defined(CSA_MODE)
int validate_eignore(_In_z_ const char *filename,
                     _In_ const PTAGGANTCONTEXT context,
                     _In_ const UNSIGNED8 *rootdata
                    )
{
    int result;
    FILE *infile;
    PTAGGANT taggant;
    PTAGGANTOBJ object;

    if (fopen_s(&infile,
                filename,
                "rb"
               )
     || !infile
       )
    {
        return ERR_BADOPEN;
    }

    taggant = NULL;

    if (((result = pTaggantGetTaggant(context,
                                      infile,
                                      TAGGANT_PEFILE,
                                      &taggant
                                     )
         ) == TNOERR
        )
     && ((result = pTaggantObjectNewEx(taggant,
                                       0,
                                       (TAGGANTCONTAINER) 0,
                                       &object
                                      )
         ) == TNOERR
        )
     && ((result = pTaggantValidateSignature(object,
                                             taggant,
                                             (PVOID) rootdata
                                            )
         ) == TNOERR
        )
       )
    {
        UNSIGNED32 size;
        char info;

        size = 0;
        result = pTaggantGetInfo(object,
                                 EIGNOREHMH,
                                 &size,
                                 &info
                                );
        pTaggantObjectFree(object);

        if (result == ERR_NONE)
        {
            result = ERR_BADLIB;
        }
        else if (result == TINSUFFICIENTBUFFER)
        {
            result = ERR_NONE;
        }
    }

    pTaggantFreeTaggant(taggant);
    fclose(infile);
    return result;
}
#endif

int validate_appended(_In_z_ const char *filename1,
                      _In_z_ const char *filename2,
                      _In_ const PTAGGANTCONTEXT context,
                      _In_ const UNSIGNED8 *rootdata,
                      TAGGANTCONTAINER tagtype,
                      int errtype
                     )
{
    int result;
    unsigned char *tmpfile;
    UNSIGNED64 tmpfile_len;

    if ((result = read_tmp_file(filename1,
                                &tmpfile,
                                &tmpfile_len
                               )
        ) == ERR_NONE
       )
    {
        if ((result = append_file(filename2,
                                  tmpfile,
                                  tmpfile_len,
                                  ERR_BADFILE
                                 )
            ) == ERR_NONE
           )
        {
            PTAGGANT taggant;
            int taglast;
            int method;

            taggant = NULL;
            result = validate_taggant(filename2,
                                      &taggant,
                                      context,
                                      rootdata,
                                      NULL,
                                      FALSE,
                                      TRUE,
                                      tagtype,
                                      &taglast,
                                      &method
                                     );
            pTaggantFreeTaggant(taggant);

            if (result == ERR_NONE)
            {
                result = ERR_BADLIB;
            }
            else if (result == errtype)
            {
                result = ERR_NONE;
            }
        }

        free(tmpfile);
    }

    return result;
}

int validate_extra(_In_z_ const char *filename,
                   _In_ const PTAGGANTCONTEXT context,
                   _In_ const UNSIGNED8 *rootdata
                  )
{
    int result;
    FILE *infile;
    PTAGGANT taggant;
    PTAGGANTOBJ object;

    if (fopen_s(&infile,
                filename,
                "rb"
               )
     || !infile
       )
    {
        return ERR_BADOPEN;
    }

    taggant = NULL;

    if (((result = pTaggantGetTaggant(context,
                                      infile,
                                      TAGGANT_PEFILE,
                                      &taggant
                                     )
         ) == TNOERR
        )
     && ((result = pTaggantObjectNewEx(taggant,
                                       0,
                                       (TAGGANTCONTAINER) 0,
                                       &object
                                      )
         ) == TNOERR
        )
     && ((result = pTaggantValidateSignature(object,
                                             taggant,
                                             (PVOID) rootdata
                                            )
         ) == TNOERR
        )
       )
    {
        UNSIGNED32 size;
        char info[sizeof(TESTSTRING2)];

        size = sizeof(info);
        result = pTaggantGetInfo(object,
                                 ECONTRIBUTORLIST,
                                 &size,
                                 info
                                );
        pTaggantObjectFree(object);
    }

    pTaggantFreeTaggant(taggant);
    fclose(infile);

    return result;
}
