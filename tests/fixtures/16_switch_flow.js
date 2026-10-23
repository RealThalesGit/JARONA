/* switch control flow: fall-through, break and continue */
function fallthrough(x) {
  let r = "";
  switch (x) {
    case 1:
      r += "a";
    case 2:
      r += "b";
      break;
    case 3:
      r += "c";
    default:
      r += "d";
  }
  return r;
}

function continueInside(x) {
  let out = [];
  for (let i = 0; i < 5; i++) {
    switch (i) {
      case 0:
        out.push("zero");
        break;
      case 1:
        continue;
      case 2:
        out.push("two");
        break;
      default:
        out.push("other");
    }
    out.push("after" + x);
  }
  return out.join(",");
}

function continueLast(x) {
  let r = "";
  for (let i = 0; i < 3; i++) {
    switch (i) {
      case 0:
        r += "a";
        break;
      default:
        continue;
    }
    r += "-";
  }
  return r;
}

function shared(x) {
  let r = "";
  switch (x) {
    case 1:
    case 2:
      r += "low";
      break;
    case 3:
      r += "three";
  }
  return r;
}

console.log(fallthrough(1), fallthrough(2), fallthrough(3), fallthrough(4));
console.log(continueInside(7));
console.log(continueLast(0));
console.log(shared(1), shared(2), shared(3), shared(4));
