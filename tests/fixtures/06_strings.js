let s = "hello world";
console.log(s.length, s.toUpperCase(), s.split(" ").join("-"));
let n = 42;
console.log(`n = ${n}, squared = ${n * n}`);
let tmpl = `multi
line
string`;
console.log(tmpl);
// template literals: the literal chunks are compiled into a "concat" chain
let t0 = `no substitution`;
let t1 = `${n} end`;
let t2 = `start ${n}`;
let t3 = `mid ${n} mid`;
let t4 = `${n}${n}`;
let t5 = `a${"b"}c`;
let t6 = `nested ${`inner ${n}`} tail`;
let t7 = `${n + 1} and ${n * 2}`;
console.log(t0, t1, t2, t3, t4, t5, t6, t7);
