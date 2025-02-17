// 导入 express 和 morgan
const express = require('express');
const morgan = require('morgan');
const sm3 = require('sm-crypto').sm3;

// 创建 Express 应用
const app = express();

// 使用 morgan 中间件来打印日志
// 'dev' 格式打印日志信息（简洁的日志格式）
app.use(morgan('dev'));

app.get('/api/user/list', (req, res) => {
    return res.send('the path is /api/user/list');
});

app.get('/project01/user/list', (req, res) => {
    return res.send('the path is /project01/user/list');
});

app.get('/api/test/hello', (req, res) => {
    return res.send('hello');
});

app.get('/api/test/headerWithHashed', (req, res) => {
    let data = 'hello';
    // --- SM3 哈希摘要 ---
    const sm3Digest = sm3(data);
    // 将16进制字符串转换为字节数组（Buffer）再转base64
    const hashed_base64 = Buffer.from(sm3Digest, 'hex').toString('base64');
    res.setHeader('hashed', hashed_base64);
    return res.send(data);
});

// 设定端口
const PORT = 3000;

// 启动服务器并监听端口
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
