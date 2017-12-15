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

#ifndef SPV_UTIL_HEADER
#define SPV_UTIL_HEADER

#include "taggant_types.h"

int erase_v1_taggant(_In_z_ const char *filename,
                     UNSIGNED8 **ppefile,
                     _Out_writes_(1) UNSIGNED64 *ppefile_len,
                     UNSIGNED32 *ptag_len
                    );

int add_hashmap(_In_ FILE *tagfile,
                _In_ PTAGGANTOBJ object,
                int badhash
               );

int create_taggant(_In_z_ const char *filename,
                   const char *outfilename,
                   _In_ const PTAGGANTCONTEXT context,
                   UNSIGNED64 version,
                   TAGGANTCONTAINER tagtype, 
                   _In_z_ const UNSIGNED8 *licdata,
                   UNSIGNED64 peobj_len,
                   UNSIGNED64 file_len,
                   UNSIGNED64 tag_off,
                   UNSIGNED32 tag_len,
                   int hashmap,
                   int badhash,
                   int puttime,
                   int filleb
                  );

int create_v1_taggant(_In_z_ const char *filename,
                      _In_ const PTAGGANTCONTEXT context,
                      _In_z_ const UNSIGNED8 *licdata,
                      UNSIGNED64 peobj_len,
                      UNSIGNED64 file_len,
                      UNSIGNED64 tag_off,
                      UNSIGNED32 tag_len,
                      int hashmap,
                      int badhash,
                      int puttime
                     );

int create_v1_v1_taggant(_In_z_ const char *filename1,
                         _In_z_ const char *filename2,
                         _In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 obj_len,
                         UNSIGNED64 file_len,
                         int puttime
                        );

int create_v2_taggant(_In_z_ const char *filename,
                      _In_ const PTAGGANTCONTEXT context,
                      TAGGANTCONTAINER tagtype, 
                      _In_z_ const UNSIGNED8 *licdata,
                      UNSIGNED64 peobj_len,
                      UNSIGNED64 file_len,
                      int hashmap,
                      int badhash,
                      int puttime,
                      int filleb
                     );

int create_v2_taggant_taggant(_In_z_ const char *filename1,
                              _In_z_ const char *filename2,
                              _In_ const PTAGGANTCONTEXT context,
                              TAGGANTCONTAINER tagtype, 
                              _In_z_ const UNSIGNED8 *licdata,
                              UNSIGNED64 peobj_len,
                              int puttime,
                              int filleb
                             );

int create_tmp_v1_taggant(_In_z_ const char *filename,
                          _In_ const PTAGGANTCONTEXT context,
                          _In_z_ const UNSIGNED8 *licdata,
                          _In_reads_(pefile_len) const UNSIGNED8 *pefile,
                          UNSIGNED64 peobj_len,
                          UNSIGNED64 pefile_len,
                          UNSIGNED64 file_len,
                          UNSIGNED64 tag_off,
                          UNSIGNED32 tag_len,
                          int hashmap,
                          int puttime
                         );

int create_tmp_v1_v2_taggant(_In_z_ const char *filename1,
                             _In_z_ const char *filename2,
                             _In_ const PTAGGANTCONTEXT context,
                             _In_z_ const UNSIGNED8 *licdata,
                             UNSIGNED64 peobj_len,
                             UNSIGNED64 tag_off,
                             int puttime
                            );

int append_v1_taggant(_In_z_ const char *filename1,
                      _In_z_ const char *filename2,
                      _In_ const PTAGGANTCONTEXT context,
                      _In_z_ const UNSIGNED8 *licdata,
                      UNSIGNED64 peobj_len,
                      UNSIGNED64 tag_off
                     );

int append_v1_v2_taggant(_In_z_ const char *filename1,
                         _In_z_ const char *filename2,
                         _In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 tag_off
                        );

int create_tampered_v1_image(_In_z_ const char *filename1,
                             _In_z_ const char *filename2,
                             _In_z_ const char *filename3,
                             const PTAGGANTCONTEXT context,
                             const UNSIGNED8 *licdata,
                             int tamper1,
                             int tamper2
                            );

int create_tampered_v1_v2_image(_In_z_ const char *filename1,
                                _In_z_ const char *filename2,
                                _In_z_ const char *filename3,
                                _In_ const PTAGGANTCONTEXT context,
                                _In_z_ const UNSIGNED8 *licdata,
                                UNSIGNED64 peobj_len,
                                UNSIGNED64 tag_off,
                                int badhash,
                                UNSIGNED64 tamper_off
                               );

int create_bad_v1_hmh(_In_z_ const char *filename1,
                      _In_z_ const char *filename2,
                      _In_ const PTAGGANTCONTEXT context,
                      _In_z_ const UNSIGNED8 *licdata,
                      _In_reads_(pefile_len) const UNSIGNED8 *pefile,
                      UNSIGNED64 peobj_len,
                      UNSIGNED64 pefile_len,
                      UNSIGNED64 file_len,
                      UNSIGNED64 tag_off,
                      UNSIGNED32 tag_len
                     );

int create_tmp_v2_taggant(_In_z_ const char *filename,
                          _In_ const PTAGGANTCONTEXT context,
                          TAGGANTCONTAINER tagtype,
                          _In_z_ const UNSIGNED8 *licdata,
                          _In_reads_(tmpfile_len) const UNSIGNED8 *tmpfile,
                          UNSIGNED64 peobj_len,
                          UNSIGNED64 tmpfile_len,
                          int hashmap,
                          int puttime
                         );

int append_v2_taggant(_In_z_ const char *filename,
                      _In_ const PTAGGANTCONTEXT context,
                      _In_z_ const UNSIGNED8 *licdata,
                      _In_reads_(pefile_len) const UNSIGNED8 *pefile,
                      UNSIGNED64 peobj_len,
                      UNSIGNED64 pefile_len
                     );

int create_tampered_v2_image(_In_z_ const char *filename1,
                             _In_z_ const char *filename2,
                             const char *filename3,
                             const PTAGGANTCONTEXT context,
                             const UNSIGNED8 *licdata,
                             UNSIGNED64 peobj_len,
                             int tamper1,
                             int tamper2,
                             int csamode
                            );

int create_bad_v2_hmh(_In_z_ const char *filename1,
                      _In_z_ const char *filename2,
                      _In_ const PTAGGANTCONTEXT context,
                      _In_z_ const UNSIGNED8 *licdata,
                      UNSIGNED64 peobj_len
                     );

int create_v3_taggant(_In_z_ const char *jsonfilename,
                      _In_z_ const char *outfilename,
                      _In_ const PTAGGANTCONTEXT context,
                      _In_z_ const UNSIGNED8 *licdata,
                      int puttime,
                      int filleb
                     );

int create_tmp_v3_taggant(_In_z_ const char *filename,
                          _In_z_ const char *jsonfilename,
                          _In_z_ const char *taggantfilename,
                          _In_reads_(tmpfile_len) const UNSIGNED8 *tmpfile,
                          UNSIGNED64 tmpfile_len
                         );

int duplicate_tag(_In_z_ const char *filename,
                  _In_z_ const UNSIGNED8 *licdata,
                  _In_reads_(pefile_len) const UNSIGNED8 *pefile,
                  UNSIGNED64 pefile_len
                 );

int create_ds(_In_z_ const char *filename1,
              _In_z_ const char *filename2,
              int mode64
             );

int create_eof(_In_z_ const char *filename,
               _In_ const PTAGGANTCONTEXT context,
               _In_z_ const UNSIGNED8 *licdata,
               const UNSIGNED8 *pefile,
               UNSIGNED64 peobj_len,
               UNSIGNED64 pefile_len
              );


#endif
