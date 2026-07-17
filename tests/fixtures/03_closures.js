function makeCounter() {
  let count = 0;
  return function () { count++; return count; };
}
const c = makeCounter();
console.log(c(), c(), c());
function adder(x) { return function (y) { return x + y; }; }
const add5 = adder(5);
console.log(add5(10));
