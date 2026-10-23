/* try/catch/finally with early returns and throws */
function finallyReturns(x) {
  try {
    if (x === 1) return "one";
    if (x === 2) return "two";
    return "many";
  } finally {
    void 0;
  }
}

function finallyNormal(x) {
  let r = "";
  try {
    r += "t";
    if (x === 1) return r + "1";
    r += "n";
  } finally {
    r += "f";
  }
  return r;
}

function catchReturns(x) {
  try {
    if (x === 1) return "one";
    if (x === 2) throw new Error("two");
    return "many";
  } catch (e) {
    return "caught:" + e.message;
  }
}

function switchInTry(x) {
  try {
    switch (x) {
      case 1: return "one";
      case 2: return "two";
      default: return "other";
    }
  } finally {
    void 0;
  }
}

function nestedTry(x) {
  try {
    try {
      if (x) throw new Error("boom");
      return "ok";
    } finally {
      if (x === 2) return "over";
    }
  } catch (e) {
    return "caught:" + e.message;
  }
}

console.log(finallyReturns(1), finallyReturns(2), finallyReturns(3));
console.log(finallyNormal(1), finallyNormal(2));
console.log(catchReturns(1), catchReturns(2), catchReturns(3));
console.log(switchInTry(1), switchInTry(2), switchInTry(3));
console.log(nestedTry(0), nestedTry(1), nestedTry(2));
