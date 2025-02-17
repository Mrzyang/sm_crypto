// 导入 express 和 morgan
const express = require('express');
const morgan = require('morgan');

// 创建 Express 应用
const app = express();

// 使用 morgan 中间件来打印日志
// 'dev' 格式打印日志信息（简洁的日志格式）
app.use(morgan('dev'));

app.get('/api/user/list', (req, res) => {
    res.send('the path is /api/user/list');
});

app.get('/project01/user/list', (req, res) => {
    res.send('the path is /project01/user/list');
});

app.get('/api/test/hello', (req, res) => {
    res.send('hello');
});

// 设定端口
const PORT = 3000;

// 启动服务器并监听端口
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
