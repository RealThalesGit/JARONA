/* every possible position of the "default" clause */
function defaultLast(x) {
  let r = "";
  switch (x) {
    case 1: r += "a"; break;
    case 2: r += "b"; break;
    default: r += "d";
  }
  return r;
}

function defaultMiddle(x) {
  let r = "";
  switch (x) {
    case 1: r += "a"; break;
    default: r += "d"; break;
    case 2: r += "b"; break;
  }
  return r;
}

function defaultFirst(x) {
  let r = "z";
  switch (x) {
    default: r = "def";
    case 9: r += "nine"; break;
    case 10: r = "ten";
  }
  return r;
}

function defaultMiddleFall(x) {
  let r = "";
  switch (x) {
    case 1: r += "a";
    default: r += "d";
    case 2: r += "b";
  }
  return r;
}

function nestedIf(x) {
  if (x > 0) {
    switch (x) {
      case 1: return "one";
      case 2: return "two";
      default:
        if (x > 10) return "big";
        return "small";
    }
  }
  return "neg";
}

console.log(defaultLast(1), defaultLast(2), defaultLast(9));
console.log(defaultMiddle(1), defaultMiddle(2), defaultMiddle(9));
console.log(defaultFirst(9), defaultFirst(10), defaultFirst(5));
console.log(defaultMiddleFall(1), defaultMiddleFall(2), defaultMiddleFall(5));
console.log(nestedIf(1), nestedIf(2), nestedIf(50), nestedIf(5), nestedIf(-1));
