const items = [{ id: 1, name: "A" }, { id: 2, name: "B" }];
function findById(list, id) {
  for (let i = 0; i < list.length; i++) {
    if (list[i].id === id) return list[i];
  }
  return null;
}
const found = findById(items, 2);
console.log(found ? found.name : "not found");
let total = 0;
items.forEach(it => { total += it.id; });
console.log("total", total);
