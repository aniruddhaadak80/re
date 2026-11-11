const util = require('../../utils/util.js');
Page({ data: { msg: 'hello' }, onLoad() { wx.request({ url: 'https://api.example.com/v1/items?page=1' }); wx.getLocation({ type: 'gcj02' }); } });
