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
#include "file_util.h"
#include "err.h"

int read_data_file(_In_z_ const char *filename,
                   _Out_ UNSIGNED8 **pdata,
                   UNSIGNED64 *pdata_len
                  )
{
    FILE *infile;
    long filelen;

    *pdata = NULL;

    if (fopen_s(&infile,
                filename,
                "rb"
               )
     || !infile
       )
    {
        return ERR_BADOPEN;
    }

    if (fseek(infile,
              0,
              SEEK_END
             )
       )
    {
        fclose(infile);
        return ERR_BADFILE;
    }

    if ((*pdata = (UNSIGNED8 *) malloc(filelen = *pdata_len = ftell(infile))) == NULL)
    {
        fclose(infile);
        return ERR_NOMEM;
    }

    if (fseek(infile,
              0,
              SEEK_SET
             )
     || ((long) fread(*pdata,
                      1,
                      filelen,
                      infile
                     ) != filelen
        )
       )
    {
        free(*pdata);
        *pdata = NULL;
		fclose(infile);
        return ERR_BADREAD;
    }

    fclose(infile);
    return ERR_NONE;
}

int read_tmp_file(_In_ const char *filename,
                  UNSIGNED8 **ptmpfile,
                  UNSIGNED64 *ptmpfile_len
                 )
{
    int result;
    FILE *tagfile;
    UNSIGNED8 *tmpfile;
    UNSIGNED64 tmpfile_len;

    result = ERR_BADOPEN;

    if (!fopen_s(&tagfile,
                 filename,
                 "rb"
                )
     && tagfile
       )
    {
        result = ERR_BADFILE;

        if (!fseek(tagfile,
                   0,
                   SEEK_END
                  )
         && ((tmpfile_len = ftell(tagfile)) != -1)
           )
        {
            result = ERR_NOMEM;

            if ((tmpfile = *ptmpfile = (UNSIGNED8 *) malloc((size_t) (*ptmpfile_len = tmpfile_len))) != NULL)
            {
                result = ERR_NONE;

                if (fseek(tagfile,
                          0,
                          SEEK_SET
                         )
                 || (fread(tmpfile,
                           1,
                           (size_t) tmpfile_len,
                           tagfile
                          ) != (size_t) tmpfile_len
                    )
                   )
                {
                    free(tmpfile);
                    result = ERR_BADFILE;
                }
            }
        }

        fclose(tagfile);
    }

    return result;
}

int create_tmp_file(_In_z_ const char *filename,
                    _In_reads_(tmpfile_len) const UNSIGNED8 *tmpfile,
                    UNSIGNED64 tmpfile_len
                   )
{
    int result;
    FILE *tagfile;

    result = ERR_BADOPEN;

    if (!fopen_s(&tagfile,
                 filename,
                 "wb+"
                )
     && tagfile
       )
    {
        result = ERR_NONE;

        if (fwrite(tmpfile,
                   1,
                   (size_t) tmpfile_len,
                   tagfile
                  ) != tmpfile_len
           )
        {
            result = ERR_BADFILE;
        }

        fclose(tagfile);
    }

    return result;
}

int append_file(_In_z_ const char *filename,
                _In_reads_(tmpfile_len) const UNSIGNED8 *tmpfile,
                UNSIGNED64 tmpfile_len,
                UNSIGNED8 value
               )
{
    int result;
    FILE *tagfile;

    if ((result = create_tmp_file(filename,
                                  tmpfile,
                                  tmpfile_len
                                 )
        ) == ERR_NONE
       )
    {
        result = ERR_BADFILE;

        if (!fopen_s(&tagfile,
                     filename,
                     "a"
                    )
         && tagfile
           )
        {
            if (fwrite(&value,
                       1,
                       1,
                       tagfile
                      ) == 1
               )
            {
                result = ERR_NONE;
            }

            fclose(tagfile);
        }
    }

    return result;
}

