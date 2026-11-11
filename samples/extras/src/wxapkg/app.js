App({ onLaunch() { wx.request({ url: 'https://api.example.com/v1/login', method: 'POST', data: { code: 'x' } }); } });
