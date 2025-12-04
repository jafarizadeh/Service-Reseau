#include <stdio.h>
#include "decode.h"


void try_telnet(const unsigned char *p, int len) {
    if (len <= 0) return;

    int i = 0, out = 0;
    char line[128];

    while (i < len && out < (int)sizeof(line) - 1) {
        unsigned char c = p[i];

        if (c == 255) { 
            if (i + 1 >= len) break;
            unsigned char cmd = p[i + 1];

            if (cmd >= 251 && cmd <= 254) { 
                i += 3;
                continue;
            }
            /* SB sub-negotiation: IAC SB ... IAC SE */
            if (cmd == 250) {
                i += 2;
                while (i + 1 < len && !(p[i] == 255 && p[i + 1] == 240)) i++;
                if (i + 1 < len) i += 2; /* skip IAC SE */
                continue;
            }
            /* other IAC (e.g., NOP/SE) */
            i += 2;
            continue;
        }

        if (c == '\r' || c == '\n') break;
        line[out++] = (c >= 32 && c <= 126) ? (char)c : '.';
        i++;
    }
    line[out] = '\0';
    if (out > 0) printf("  TELNET: %s\n", line);
}
