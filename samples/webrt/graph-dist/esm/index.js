import {
  require_helpers
} from "./chunk-5QXAPRUV.js";
import {
  startA
} from "./chunk-KSII6XAB.js";
import {
  __commonJS,
  __require,
  __toESM
} from "./chunk-PIRHQTI4.js";

// src/legacy.cjs
var require_legacy = __commonJS({
  "src/legacy.cjs"(exports, module) {
    var helpers = require_helpers();
    var path = __require("path");
    module.exports = { version: helpers.version(), base: path.basename("/x/y") };
  }
});

// src/util/strings.ts
function slug(s, o) {
  return s.toLowerCase().replace(/\s+/g, o?.sep ?? "-");
}

// src/index.js
var import_legacy = __toESM(require_legacy());
import { debounce } from "lodash-es";
async function main(name) {
  startA();
  const s = slug(name);
  const { lazyThing } = await import("./chunk-HS4K5ZBH.js");
  return debounce(() => lazyThing(s, import_legacy.default.version), 10);
}
export {
  main
};
