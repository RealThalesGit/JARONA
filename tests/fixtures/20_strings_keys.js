/* string literals and property keys that are not plain identifiers */
function literals() {
  return [
    "AIM-TEST",
    "o'lá",
    "line1\nline2",
    "tab\there",
    "back\\slash",
    "quote\"inside",
    "a\u0000b",
    "",
    "0123",
    "has space",
  ].join("|");
}

function objectKeys() {
  const o = {
    "AIM-TEST": 1,
    "com espaço": 2,
    123: 3,
    ok: 4,
    "com\"aspa": 5,
    "": 6,
  };
  return [o["AIM-TEST"], o["com espaço"], o["123"], o.ok, o['com"aspa'], o[""]].join(",");
}

class Weird {
  "AIM-TEST"() { return 7; }
  "with space"() { return 8; }
  get "weird-get"() { return 9; }
  static "static-name"() { return 10; }
  normal() { return 11; }
}

function classKeys() {
  const w = new Weird();
  return [w["AIM-TEST"](), w["with space"](), w["weird-get"], Weird["static-name"](), w.normal()].join(",");
}

console.log(literals().length > 0);
console.log(objectKeys());
console.log(classKeys());
