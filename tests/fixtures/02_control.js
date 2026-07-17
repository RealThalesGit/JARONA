function classify(n) {
  if (n < 0) return "negative";
  else if (n === 0) return "zero";
  else if (n < 10) return "small";
  else return "large";
}
let i = 0;
while (i < 5) { console.log(i); i++; }
for (let j = 0; j < 3; j++) { console.log("j", j); }
let arr = [1, 2, 3];
for (let v of arr) console.log("v", v);
console.log(classify(7));
