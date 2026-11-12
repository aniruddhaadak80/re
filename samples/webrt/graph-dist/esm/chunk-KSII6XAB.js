// src/b.js
function b() {
  return c();
}

// src/a.js
function startA() {
  return b() + 1;
}
var A_NAME = "a";

// src/c.js
function c() {
  return A_NAME.length;
}

export {
  c,
  startA
};
