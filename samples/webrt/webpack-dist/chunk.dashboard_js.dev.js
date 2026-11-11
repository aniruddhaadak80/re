"use strict";
(self["webpackChunk"] = self["webpackChunk"] || []).push([["dashboard_js"],{

/***/ "./dashboard.js"
/*!**********************!*\
  !*** ./dashboard.js ***!
  \**********************/
(__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   renderDashboard: () => (/* binding */ renderDashboard)
/* harmony export */ });
function renderDashboard(user) {
  const el = document.createElement('div');
  el.textContent = 'Dashboard for ' + user.id;
  navigator.sendBeacon('/telemetry/dashboard-open', JSON.stringify({ id: user.id }));
  document.body.appendChild(el);
}


/***/ }

}]);