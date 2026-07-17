#!/bin/sh
# Extract raw QuickJS bytecode from a qjsc-generated C file.
# Usage: extract_bytecode.sh input.c output.bin
awk '
/^const uint32_t qjsc_/ { next }
/^const uint8_t qjsc_/  { next }
/^[ \t]*0x[0-9a-fA-F]+/ {
    # split line on commas
    line = $0
    sub(/\}[ \t]*;[ \t]*$/, "", line)
    n = split(line, parts, ",")
    for (i = 1; i <= n; i++) {
        s = parts[i]
        gsub(/[ \t]+/, "", s)
        if (s ~ /^0x/) {
            v = strtonum(s)
            printf "%c", v
        }
    }
}
' "$1" > "$2"
