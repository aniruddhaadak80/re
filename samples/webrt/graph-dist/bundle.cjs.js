var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __esm = (fn, res, err) => function __init() {
  if (err) throw err[0];
  try {
    return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
  } catch (e) {
    throw err = [e], e;
  }
};
var __commonJS = (cb, mod) => function __require() {
  try {
    return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
  } catch (e) {
    throw mod = 0, e;
  }
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/c.js
function c() {
  return A_NAME.length;
}
var init_c = __esm({
  "src/c.js"() {
    init_a();
  }
});

// src/b.js
function b() {
  return c();
}
var init_b = __esm({
  "src/b.js"() {
    init_c();
  }
});

// src/a.js
function startA() {
  return b() + 1;
}
var A_NAME;
var init_a = __esm({
  "src/a.js"() {
    init_b();
    A_NAME = "a";
  }
});

// src/helpers.cjs
var require_helpers = __commonJS({
  "src/helpers.cjs"(exports2) {
    exports2.version = function version() {
      return "1.2.3";
    };
  }
});

// src/legacy.cjs
var require_legacy = __commonJS({
  "src/legacy.cjs"(exports2, module2) {
    var helpers = require_helpers();
    var path = require("path");
    module2.exports = { version: helpers.version(), base: path.basename("/x/y") };
  }
});

// src/lazy.js
var lazy_exports = {};
__export(lazy_exports, {
  lazyThing: () => lazyThing
});
function lazyThing(s, v) {
  return `${s}:${v}:${c()}`;
}
var init_lazy = __esm({
  "src/lazy.js"() {
    init_c();
  }
});

// src/index.js
var index_exports = {};
__export(index_exports, {
  main: () => main
});
module.exports = __toCommonJS(index_exports);
init_a();

// src/util/strings.ts
function slug(s, o) {
  return s.toLowerCase().replace(/\s+/g, o?.sep ?? "-");
}

// src/index.js
var import_lodash_es = require("lodash-es");
var import_legacy = __toESM(require_legacy());
async function main(name) {
  startA();
  const s = slug(name);
  const { lazyThing: lazyThing2 } = await Promise.resolve().then(() => (init_lazy(), lazy_exports));
  return (0, import_lodash_es.debounce)(() => lazyThing2(s, import_legacy.default.version), 10);
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  main
});
//# sourceMappingURL=bundle.cjs.js.map
