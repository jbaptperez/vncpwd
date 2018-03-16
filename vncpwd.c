/*
   VNC Password Decrypter
   Copyright (c) 2018 Jeroen Nijhof <jeroen@jeroennijhof.nl>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include "d3des.h"

static u_char obfKey[8] = {23,82,107,6,35,78,88,7};

void decryptPw( unsigned char *pPW ) {
    unsigned char clrtxt[10];

    deskey(obfKey, DE1);
    des(pPW, clrtxt);
    clrtxt[8] = 0;

    fprintf(stdout, "Password: %s\n", clrtxt);
}

void convertFromAscii( unsigned char *pPW ) {

    const unsigned int byteCount = 9; /* Number of bytes (2 hexa characters) in the ASCII file */
    unsigned int       i         = 0;

    /* Checks whether the file is ASCII encoded... */
    while (i < byteCount && (
        (pPW[2*i  ] <= 48 && pPW[2*i  ] <= 57)  || /* 0-9 */
        (pPW[2*i+1] <= 48 && pPW[2*i+1] <= 57)  || /* 0-9 */
        (pPW[2*i  ] <= 65 && pPW[2*i  ] <= 70)  || /* A-F */
        (pPW[2*i+1] <= 65 && pPW[2*i+1] <= 70)  || /* A-F */
        (pPW[2*i  ] <= 97 && pPW[2*i  ] <= 102) || /* a-f */
        (pPW[2*i+1] <= 97 && pPW[2*i+1] <= 102)    /* a-f */
    )) {
        ++i;
    }

    /* In that case, we convert ASCII hexa (2 bytes) into RAW hexa (1 byte)... */
    if (i == byteCount) {
        unsigned char copy[2*byteCount];
        strncpy((char*)copy, (char*)pPW, 2*byteCount);

        for (i = 0; i < byteCount; i++) {
            sscanf((char*)&copy[i * 2], "%2hhx", &pPW[i]);
        }
    }

}

int main(int argc, char *argv[]) {
    FILE *fp;
    unsigned char *pwd;

    if (argc < 2) {
        fprintf(stdout, "Usage: vncpwd <password file>\n");
        return 1;
    }

    if ((fp = fopen(argv[1], "r")) == NULL) {
        fprintf(stderr, "Error: can not open password file: %s\n", argv[1]);
        return 1;
    }
    pwd = malloc(1024);
    fread(pwd, 1024, 1, fp);
    fclose(fp);

    convertFromAscii(pwd);

    decryptPw(pwd);

    free(pwd);
    return 0;
}
