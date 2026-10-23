# split_modules.awk - split the decompiler output into one file per module.
#
# The decompiler prints every module of a byte code file with a header
# line:
#
#     /* ===== Module: <name> ===== */
#
# This script writes the code that follows such a header into
# "<outdir>/<name>".  Module names that contain a path are created
# recursively.
#
# Usage: awk -v outdir=<dir> -f split_modules.awk <decompiled.js>

BEGIN {
    file = ""
}

{
    if ($0 ~ /^\/\* ===== Module: .* ===== \*\/$/) {
        name = $0
        sub(/^\/\* ===== Module: /, "", name)
        sub(/ ===== \*\/$/, "", name)
        sub(/^\.\//, "", name)

        file = outdir "/" name
        if (index(name, "/") > 0) {
            dir = name
            sub(/\/[^/]*$/, "", dir)
            system("mkdir -p \"" outdir "/" dir "\"")
        }
        # truncate the file
        printf "" > file
        next
    }
    if (file != "")
        print $0 >> file
}
