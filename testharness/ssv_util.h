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
 */

#ifndef SSV_UTIL_HEADER
#define SSV_UTIL_HEADER

#include "taggant_types.h"

enum
{
    METHOD_HMH,
    METHOD_FFH
};

enum
{
    TAMPER_NONE,
    TAMPER_FILELEN,
    TAMPER_FILELENM1,
    TAMPER_FILELENM2,
    TAMPER_TAGP101,
    TAMPER_FILELENM2P101,
    TAMPER_TIME,
    TAMPER_3
};

enum
{
    TAG_1,
    TAG_2,
    TAG_3,
    TAG_1_HMH,
    TAG_2_HMH,
    TAG_2_1_HMH,
    TAG_1_1,
    TAG_1_FFH,
    TAG_2_FFH
};

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
                    );

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
                            );

int validate_taggant_taggant_taggant(_In_ const char *filename,
                                     __deref_inout PTAGGANT *ptaggant,
                                     _In_ const PTAGGANTCONTEXT context,
                                     _In_ const UNSIGNED8 *rootdata,
                                     _In_opt_ const UNSIGNED8 *tsrootdata,
                                     int gettime,
                                     int ignorehmh,
                                     TAGGANTCONTAINER tagtype
                                    );

int validate_no_taggant(_In_z_ const char *filename1,
                        _In_z_ const char *filename2,
                        _In_ const PTAGGANTCONTEXT context
                       );

int validate_tampered(_In_opt_z_ const char *filename1,
                      _In_z_ const char *filename2,
                      _In_ const PTAGGANTCONTEXT context,
                      _In_ const UNSIGNED8 *rootdata,
                      int tamper_lvl,
                      int tag_lvl
                     );

#if defined(CSA_MODE)
int validate_eignore(_In_z_ const char *filename,
                     _In_ const PTAGGANTCONTEXT context,
                     _In_ const UNSIGNED8 *rootdata
                    );
#endif

int validate_appended(_In_z_ const char *filename1,
                      _In_z_ const char *filename2,
                      _In_ const PTAGGANTCONTEXT context,
                      _In_ const UNSIGNED8 *rootdata,
                      TAGGANTCONTAINER tagtype,
                      int errtype
                     );

int validate_extra(_In_z_ const char *filename,
                   _In_ const PTAGGANTCONTEXT context,
                   _In_ const UNSIGNED8 *rootdata
                  );

#endif
