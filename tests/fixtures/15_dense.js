let x = 1 + 2 * 3 - 4 / 2;
let y = (x << 2) | 255;
let z = x > 0 ? y & 15 : ~y;
console.log(x, y, z);
