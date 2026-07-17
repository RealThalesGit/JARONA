function add(a, b) { return a + b; }
function fib(n) {
  if (n < 2) return n;
  return fib(n - 1) + fib(n - 2);
}
let x = add(3, 4);
console.log("x =", x);
console.log("fib(10) =", fib(10));
