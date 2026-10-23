# JARONA - QuickJS Bytecode Decompiler

A standalone, dependency-free QuickJS bytecode decompiler written in pure C. It parses QuickJS compiled bytecode directly and reconstructs structured JavaScript without linking against QuickJS.

## Features

- **Standalone** - No QuickJS runtime dependency. Parses the binary format directly.
- **Broad compatibility** - Handles bytecode from multiple QuickJS versions, including Bignum.
- **Auto-detection** - Endianness, bytecode format, version and built-in atom table are detected automatically. Supports `QBCF`-wrapped binaries.
- **Output modes**
  - Text disassembly (default)
  - JSON (`-j`) for structured inspection
  - Pseudo-JS decompilation (`-d`) to reconstruct source-level structure
  - Hex dump (`-x`)
- **Recursive analysis** - Walks functions, closures and modules.
- **Control flow reconstruction** - `if`/`else`, `while`, `do`/`while`, `for`, `for...of`/`for...in`, `try`/`catch`/`finally`, `break`/`continue`, labelled loops, `switch` with fall-through/default, and `goto` where unresolvable.
- **Expression reconstruction** - Operator precedence, ternary, short-circuit (`&&`/`||`), nullish coalescing (`??`), optional chaining (`?.`), template literals, tagged templates, array/object literals, spread/rest, computed keys, getters/setters, classes, inheritance, private fields, generators, `async/await`, destructuring, default parameters.
- **Atom resolution** - Built-in atoms + user atoms from the atom table, with vanilla/Frida tables.
- **Binding sanitization** - Bindings with invalid identifier characters are sanitized deterministically across all uses. String literals and property keys are never renamed. Internal QuickJS identifiers like `this`, `this.active_func`, `new.target`, `home_object`, `arguments` are preserved.

## Build

```bash
make
```

Produces `jarona-decompile`.

Requirements: C compiler (gcc/clang), standard library, make. No external dependencies.

## Usage

```text
jarona-decompile [options] <bytecode_file>

Options:
  -c, --compiled        Treat input as compiled binary (search for QBCF magic)
  -j, --json            Output JSON-structured data
  -d, --decompile       Output pseudo-JS decompilation
  -s, --stats           Print statistics to stderr
  -a, --atoms           Print atom table to stderr
  -x, --hex             Print a hex dump of the bytecode payload
      --vanilla         Force the vanilla QuickJS built-in atom table
      --frida           Force Frida's QuickJS built-in atom table
  -o, --output <file>   Write output to file (default: stdout)
  -h, --help            Show help
```

Format, endianness, version and atom table are detected automatically.

Examples:

```bash
# Disassemble
jarona-decompile test.qjsc

# Extract from compiled binary
jarona-decompile -c program

# Decompile to JavaScript
jarona-decompile -d test.qjsc > out.js

# JSON
jarona-decompile -j test.qjsc > out.json
```

## Project Structure

```text
.
├── Makefile
├── README.md
├── src
│   ├── decompile.h
│   ├── decompile2.c        # Decompiler: IR -> structured JavaScript
│   ├── disasm.c            # Disassembler (text/JSON)
│   ├── disasm.h
│   ├── expr.h              # Expression precedence/helpers
│   ├── ir.c                # Instruction IR, labels, branch targets
│   ├── ir.h
│   ├── main.c              # CLI
│   ├── qjs_atoms.c
│   ├── qjs_builtin_atoms.h
│   ├── qjs_format.h        # Bytecode format definitions
│   ├── qjs_opcodes.c
│   ├── qjs_opcodes.h
│   ├── qjs_opcodes_enum.inc
│   ├── qjs_opcodes_frida.inc
│   ├── qjs_opcodes_vanilla.inc
│   ├── reader.c            # Binary reader with bounds checking
│   ├── reader.h
│   ├── util.c              # Memory/endian/LEB128 helpers
│   ├── util.h
│   └── value.c             # Value/parser for constants/functions/modules
├── tests
│   ├── extract_bytecode
│   ├── extract_bytecode.c
│   ├── extract_bytecode.sh
│   ├── fixtures/           # Test fixtures
│   ├── make-fixtures.sh
│   ├── modules/
│   ├── run-behaviour.sh
│   ├── run-modules.sh
│   ├── run-sanitize.sh
│   ├── run-tests.sh
│   └── split_modules.awk
└── tools
    ├── frida-quickjs-opcode.h
    ├── gen_opcodes.sh
    └── quickjs-opcode.h
```

### Opcode tables

`src/qjs_opcodes_*.inc` are generated from vendored headers and must not be edited by hand.

```bash
make opcodes        # regenerate
make check-opcodes  # verify
make check          # run checks
```

### Binding sanitization

Bindings with non-identifier text are rewritten deterministically across declarations, assignments and references. String literals and property keys are preserved verbatim. Covered by `tests/run-sanitize.sh`.

## How It Works

### Binary format
QuickJS bytecode: header (`BC_VERSION`, endianness encoded), atom table (LEB128 count + length-prefixed strings), then top-level tagged value (usually function bytecode or module). Functions contain header, variable definitions, closure vars, bytecode, optional debug info and constant pool.

### Atom resolution
Atoms are 32-bit identifiers: tagged ints, built-ins (< 228), or user atoms from the atom table. All are resolved to strings.

### Decompilation
A virtual stack tracks expressions as opcodes execute. Statements are built via IR (`ir.h`) with structured control flow recovery (if/else/loops/switch/try/catch/finally). Pattern recognizers rebuild complex forms; unknown patterns fall back to generic reconstruction.

## Limitations

- Best-effort reconstruction; heavily optimized bytecode may be non-idiomatic.
- Some `break`/`continue` across `try`/`finally` may duplicate inlined `finally` bodies.
- Class method names may not always be recovered.
- Bindings that require sanitization are renamed textually (behavior preserved). Strings/keys unchanged.
- Debug line info not emitted.
- Typed arrays/shared array buffers only partially supported.
