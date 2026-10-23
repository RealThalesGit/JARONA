/* Binding names that the sanitizer may have to rewrite.
 *
 * The source itself uses ordinary identifiers - invalid ones cannot be
 * compiled - but the companion test (tests/run-sanitize.sh) patches the
 * atom table of the compiled byte code so that "compute" / "counter"
 * become "compu-t" / "count-r" and checks the decompiler turns them back
 * into valid identifiers while leaving the string literals below intact. */
const label = "keep-me";

function compute(a, b) {
  const counter = a + b;
  return counter + label;
}

function main() {
  const values = [compute(20, 21), label];
  return values.join(" ");
}

console.log(main());
