# JARONA - QuickJS Bytecode Decompiler

A standalone, dependency-free QuickJS bytecode decompiler written in pure C.
Refactored from the original `frida-decompile.c` (which depended on QuickJS internals)
into a clean, modular architecture that can decompile **any** QuickJS-compiled bytecode.

## Features

- **Standalone** - No QuickJS runtime dependency. Parses the binary format directly.
- **Universal** - Handles bytecode from any QuickJS version (v1 / v2 / Bignum).
- **Endian-aware** - Auto-detects big-endian vs little-endian bytecode.
- **QBCF extraction** - Auto-detects and unwraps `QBCF`-embedded bytecode in compiled binaries.
- **Three output modes**:
  - **Text assembly** (default) - Human-readable opcode listing
  - **JSON** (`-j`) - Structured JSON for programmatic consumption
  - **Pseudo-JS** (`-d`) - Best-effort decompilation to JavaScript-like source
- **Recursive** - Walks nested functions, closures, and modules depth-first.
- **Full opcode coverage** - All 248 QuickJS opcodes (including short opcodes).
- **Atom resolution** - Built-in atoms (228) + user atoms from the atom table.

## Build

```bash
make
```

This produces the `jarona-decompile` binary.

### Requirements

- A C compiler (gcc or clang)
- Standard C library
- Make

No external libraries needed!

## Usage

```
jarona-decompile [options] <bytecode_file>

Options:
  -c, --compiled        Treat input as compiled binary (search for QBCF magic)
  -j, --json            Output JSON-structured data
  -d, --decompile       Output pseudo-JS decompilation
  -s, --stats           Print statistics to stderr
  -a, --atoms           Print atom table to stderr
  -o, --output <file>   Write output to file (default: stdout)
  -h, --help            Show help
```

### Examples

```bash
# Disassemble raw bytecode
jarona-decompile test.qjsc

# Extract QBCF from a compiled binary
jarona-decompile -c program

# Pseudo-decompile to JS
jarona-decompile -d test.qjsc > out.js

# Structured JSON
jarona-decompile -j test.qjsc > out.json

# Show atom table + statistics
jarona-decompile -a -s test.qjsc > /dev/null
```

## Architecture

```
jarona-decompile/
├── Makefile
├── README.md
└── src/
    ├── main.c                   # CLI entry point
    ├── qjs_format.h             # Bytecode format definitions
    ├── qjs_opcodes.h            # Opcode table (248 opcodes)
    ├── qjs_builtin_atoms.h      # Built-in atom strings (228 atoms, generated)
    ├── util.h / util.c          # Memory, endian, LEB128 helpers
    ├── reader.h / reader.c      # Binary reader with bounds checking
    ├── value.h / value.c        # Recursive value parser (constants/functions/modules)
    ├── disasm.h / disasm.c      # Disassembler (text + JSON output)
    └── decompile.h / decompile.c # Pseudo-decompiler (bytecode -> JS)
```

## Output Examples

### Text assembly (default)

```
; ===== Function #1: function add =====
;   args=2  vars=0  defined_args=2  stack_size=2
;   closure_vars=0  cpool=0  bytecode_len=4  locals=2
; ----- Locals / Args (2) -----
;   [ 0] a                    scope=0 next=0 kind=0
;   [ 1] b                    scope=0 next=0 kind=0
; ----- Bytecode (4 bytes) -----
[0x0000] get_arg0                    ; stack -0 +1
[0x0001] get_arg1                    ; stack -0 +1
[0x0002] add                         ; stack -2 +1
[0x0003] return                      ; stack -1 +0
```

### Pseudo-JS decompilation (`-d`)

```
function add(a, b) {
  return (a + b);
}

function fib(n) {
  if (!(n < 2)) goto L0008;
  return n;
  return (fib((n - 1)) + fib((n - 2)));
}

function <eval>() {
  result = add(3, 4);
  console.log("Result:", result);
  console.log("Fib(10):", fib(10));
}
```

### JSON (`-j`)

```json
{
  "file": "test.qjsc",
  "size": 280,
  "bytecode_size": 280,
  "big_endian": false,
  "atom_count": 10,
  "functions": [
    {
      "index": 1,
      "name": "add",
      "kind": "function",
      "arg_count": 2,
      "bytecode_len": 4,
      "bytecode": [
        {"pc": 0, "op": "get_arg0", "size": 1, "pop": 0, "push": 1},
        {"pc": 1, "op": "get_arg1", "size": 1, "pop": 0, "push": 1},
        {"pc": 2, "op": "add", "size": 1, "pop": 2, "push": 1},
        {"pc": 3, "op": "return", "size": 1, "pop": 1, "push": 0}
      ]
    }
  ]
}
```

## How It Works

### Binary format

QuickJS bytecode files have the following structure:

1. **Header**: `BC_VERSION` byte (1 or 2 for Bignum, `| 0x40` for big-endian)
2. **Atom table**: LEB128 count, then length-prefixed strings (8-bit or 16-bit)
3. **Top-level value**: A tagged value (usually `BC_TAG_FUNCTION_BYTECODE` = 14 or `BC_TAG_MODULE` = 15)

Functions contain:
- Header (flags, js_mode, func_name, arg_count, var_count, etc.)
- Variable definitions (locals + args, with scope info)
- Closure variables
- Bytecode body (raw opcodes)
- Debug info (filename, line number, pc2line data) - optional
- Constant pool (recursive values, can contain nested functions)

### Atom resolution

QuickJS atoms are 32-bit identifiers for strings. They can be:
- **Tagged-int atoms** (bit 31 set): represent integer property keys
- **Built-in atoms** (index < `JS_ATOM_END` = 228): pre-defined strings like "length", "prototype", etc.
- **User atoms** (index >= `JS_ATOM_END`): strings from the file's atom table

The decompiler resolves all three types and displays the actual string.

### Pseudo-decompilation

The decompiler uses a **virtual stack** to track expressions:
1. Each opcode that pushes a value adds a string representation to the virtual stack
2. Opcodes that consume values pop them and build composite expressions
3. Side-effect operations (assignments, returns, calls) are emitted as statements

This produces readable JS-like output that approximates the original source.

## Limitations

- Pseudo-decompilation is **best-effort**. Some patterns (complex control flow, optimized
  sequences) may produce non-idiomatic JS.
- Class method names are not always recoverable (they're stored in `define_method` atoms,
  not in the function header).
- Some debug info (line numbers from `pc2line`) is parsed but not used for output.
- Typed arrays and shared array buffers are recognized but not fully decoded.

## Comparison to original frida-decompile.c

| Feature | frida-decompile.c | jarona-decompile |
|---------|-------------------|-----------------|
| QuickJS dependency | `#include "quickjs.c"` (heavy) | None (standalone) |
| Binary format parsing | Via `JS_ReadObject` | Direct binary parsing |
| Output formats | printf only | Text, JSON, pseudo-JS |
| Atom resolution | Via QuickJS runtime | Built-in table + user atoms |
| Constant pool display | Basic tags | Full recursive value formatting |
| Control flow | Flat listing | Label resolution + markers |
| Decompilation | None | Pseudo-JS with virtual stack |
| Code size | 877 lines | ~3500 lines (modular) |

(frida-decompile.c is a old thing though...)

## License

Same as the original JARONA project.
