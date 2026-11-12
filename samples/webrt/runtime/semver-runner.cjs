// Calls into the esbuild bundle of semver 7.7.1 so the tracer and reconciler have real bundle code to map.
const semver = require('../shapes/semver-7.7.1.bundle.cjs');
const results = [semver.satisfies('1.2.3', '^1.0.0'), semver.compare('1.2.3', '1.10.0'), semver.parse('2.0.0-rc.1').prerelease.join('.')];
setTimeout(() => console.log(JSON.stringify(results)), 5);
