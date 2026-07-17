function* range(start, stop) {
  for (let i = start; i < stop; i++) yield i;
}
async function fetchData() {
  await new Promise(r => setTimeout(r, 1));
  return { ok: true };
}
for (let v of range(0, 5)) console.log("gen", v);
