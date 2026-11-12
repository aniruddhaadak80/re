const helpers = require('./helpers.cjs');
const path = require('path');
module.exports = { version: helpers.version(), base: path.basename('/x/y') };
