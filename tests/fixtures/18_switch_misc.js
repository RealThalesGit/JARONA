/* switches combined with other constructs */
function stringCases(x) {
  let r = "";
  switch (x) {
    case "a": r = "A"; break;
    case "b": r = "B"; break;
    case 3: r = "three";
  }
  return r;
}

function nested(x) {
  let r = 0;
  switch (x) {
    case 1:
      switch (x + 1) {
        case 2: r = 12; break;
        case 3: r = 13; break;
      }
      r += 100;
      break;
    case 2:
      r = 20;
  }
  return r;
}

function inTry(x) {
  let r = 0;
  try {
    switch (x) {
      case 1: throw new Error("one");
      default: r = 5;
    }
  } catch (err) {
    r = -1;
  }
  return r;
}

function inForOf(x) {
  let r = [];
  for (const v of [1, 2, 3]) {
    switch (v) {
      case 1: continue;
      case 2: r.push("two"); break;
    }
    r.push("v" + v);
  }
  return r.join(",");
}

function returnsOnly(x) {
  switch (x) {
    case 1: return "1";
    case 2: return "2";
    case 3: return "3";
  }
  return "none";
}

console.log(stringCases("a"), stringCases("b"), stringCases(3), stringCases("z"));
console.log(nested(1), nested(2));
console.log(inTry(1), inTry(2));
console.log(inForOf(0));
console.log(returnsOnly(1), returnsOnly(2), returnsOnly(3), returnsOnly(4));
