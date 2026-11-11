const sea = require('node:sea');
console.log('hello from sea', sea.isSea(), sea.getAsset('greeting.txt', 'utf8'));
