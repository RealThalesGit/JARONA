const obj = { a: 1, b: "two", c: [3, 4, 5], nested: { x: true } };
console.log(obj.a, obj.b, obj.c[1], obj.nested.x);
const { a, b } = obj;
console.log(a, b);
const arr = [10, 20, 30];
const [p, q, r] = arr;
console.log(p, q, r);
