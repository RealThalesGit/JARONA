/* Extract raw QuickJS bytecode from a qjsc-generated C source file. */
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s input.c output.bin\n", argv[0]); return 1; }
    FILE *in = fopen(argv[1], "r");
    if (!in) { perror("fopen input"); return 1; }
    FILE *out = fopen(argv[2], "wb");
    if (!out) { perror("fopen output"); fclose(in); return 1; }
    int c, n = 0;
    while ((c = fgetc(in)) != EOF) {
        if (c == '0' && (tolower(fgetc(in)) == 'x')) {
            int hi = fgetc(in), lo = fgetc(in);
            int hv = (hi <= '9') ? hi - '0' : tolower(hi) - 'a' + 10;
            int lv = (lo <= '9') ? lo - '0' : tolower(lo) - 'a' + 10;
            if (hv >= 0 && hv < 16 && lv >= 0 && lv < 16) {
                fputc((hv << 4) | lv, out);
                n++;
            }
        }
    }
    fclose(in); fclose(out);
    fprintf(stderr, "extracted %d bytes\n", n);
    return 0;
}
