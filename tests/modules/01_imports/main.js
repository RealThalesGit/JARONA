import { A, B as C } from "./dep.js";
import def from "./dep.js";
import * as ns from "./dep.js";

export { A };
export { C as renamed };

export const local = A + C;

console.log(local, def, ns, A, C);
