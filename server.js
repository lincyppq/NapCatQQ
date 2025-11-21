
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const cron = require('node-cron');
const multer = require('multer');
const axios = require('axios');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// --- 配置 ---
const PORT = 54321;
const JWT_SECRET = 'napcat-secret-key-change-this'; // 实际生产请修改
const DB_FILE = path.join(__dirname, 'bots.json');
const ADMIN_FILE = path.join(__dirname, 'admin.json');
const AUDIT_FILE = path.join(__dirname, 'audit.json');
const LOGIN_HISTORY_FILE = path.join(__dirname, 'login_history.json');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const BACKUPS_DIR = path.join(__dirname, 'backups');

// --- 目录初始化 ---
[UPLOADS_DIR, BACKUPS_DIR].forEach(dir => {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir);
});

// --- Multer 上传配置 ---
const storage = multer.diskStorage({
    destination: function (req, file, cb) { cb(null, UPLOADS_DIR) },
    filename: function (req, file, cb) {
        const ext = path.extname(file.originalname);
        cb(null, Date.now() + ext);
    }
});
const upload = multer({ storage: storage });

// --- 初始化数据 ---
let adminConfig = {
    username: 'admin',
    password: 'admin123',
    defaultNotifyMessage: '[系统通知] 本群机器人服务已到期，请联系管理员续费。',
    warningDays: 3,
    warningMessage: '[温馨提醒] 本群机器人服务即将到期，请及时续费以免影响使用。',
    renewalMessage: '请联系管理员进行续费。\n支持微信/支付宝。',
    backupRetentionDays: 7,
    // 自动退群策略
    autoQuit: false, 
    quitWaitHours: 24,
    quitMessage: '[服务结束] 由于服务到期未续费，机器人将自动退出本群。感谢使用，江湖再见。',
    uiTheme: {
        primaryColor: '#007AFF', // Apple System Blue
        backgroundImage: '',
        overlayOpacity: 0.4 
    }
};

let logs = [];
let loginHistory = [];

if (fs.existsSync(ADMIN_FILE)) {
    try {
        const savedConfig = JSON.parse(fs.readFileSync(ADMIN_FILE, 'utf8'));
        adminConfig = { ...adminConfig, ...savedConfig };
        if (!adminConfig.uiTheme) {
            adminConfig.uiTheme = { primaryColor: '#007AFF', backgroundImage: '', overlayOpacity: 0.4 };
        }
    } catch (e) { console.error("读取管理员配置失败"); }
} else {
    fs.writeFileSync(ADMIN_FILE, JSON.stringify(adminConfig, null, 2));
}

if (fs.existsSync(AUDIT_FILE)) {
    try { logs = JSON.parse(fs.readFileSync(AUDIT_FILE, 'utf8')); } catch (e) {}
}

if (fs.existsSync(LOGIN_HISTORY_FILE)) {
    try { loginHistory = JSON.parse(fs.readFileSync(LOGIN_HISTORY_FILE, 'utf8')); } catch (e) {}
}

const saveAdminConfig = () => fs.writeFileSync(ADMIN_FILE, JSON.stringify(adminConfig, null, 2));

// --- 日志系统 ---
const writeLog = (type, action, details) => {
    const entry = {
        id: Date.now().toString(36) + Math.random().toString(36).substr(2, 5),
        time: Date.now(),
        type, // 'SYSTEM', 'USER', 'BOT'
        action,
        details
    };
    logs.unshift(entry);
    if (logs.length > 500) logs = logs.slice(0, 500);
    fs.writeFile(AUDIT_FILE, JSON.stringify(logs, null, 2), () => {});
};

// --- 登录历史记录 ---
const getIpLocation = async (ip) => {
    if (!ip || ip === '::1' || ip === '127.0.0.1' || ip.startsWith('192.168')) {
        return '本地/局域网';
    }
    try {
        const res = await axios.get(`http://ip-api.com/json/${ip}?lang=zh-CN`, { timeout: 3000 });
        if (res.data.status === 'success') {
            return `${res.data.country} ${res.data.regionName} ${res.data.city}`;
        }
        return '未知位置';
    } catch (e) {
        return '查询失败';
    }
};

const recordLogin = async (username, ip, success) => {
    const cleanIp = ip.replace(/^::ffff:/, '');
    const entry = {
        id: Date.now().toString(36) + Math.random().toString(36).substr(2, 5),
        time: Date.now(),
        username,
        ip: cleanIp,
        location: '查询中...',
        status: success
    };
    loginHistory.unshift(entry);
    if (loginHistory.length > 200) loginHistory = loginHistory.slice(0, 200);
    fs.writeFile(LOGIN_HISTORY_FILE, JSON.stringify(loginHistory, null, 2), () => {});

    try {
        const location = await getIpLocation(cleanIp);
        entry.location = location;
        fs.writeFile(LOGIN_HISTORY_FILE, JSON.stringify(loginHistory, null, 2), () => {});
    } catch (e) { console.error("IP location update failed", e); }
};

// --- 备份系统 ---
const performBackup = () => {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupPath = path.join(BACKUPS_DIR, `backup-${timestamp}`);
    
    try {
        if (fs.existsSync(DB_FILE)) fs.copyFileSync(DB_FILE, `${backupPath}-bots.json`);
        if (fs.existsSync(ADMIN_FILE)) fs.copyFileSync(ADMIN_FILE, `${backupPath}-admin.json`);
        
        writeLog('SYSTEM', 'BACKUP_CREATED', `Backup created: ${timestamp}`);
        
        const retentionMs = (adminConfig.backupRetentionDays || 7) * 24 * 60 * 60 * 1000;
        const files = fs.readdirSync(BACKUPS_DIR);
        const now = Date.now();
        
        files.forEach(file => {
            const filePath = path.join(BACKUPS_DIR, file);
            const stats = fs.statSync(filePath);
            if (now - stats.mtimeMs > retentionMs) {
                fs.unlinkSync(filePath);
                console.log(`Deleted old backup: ${file}`);
            }
        });
    } catch (e) {
        writeLog('SYSTEM', 'BACKUP_FAILED', e.message);
        console.error("Backup failed", e);
    }
};

// --- 中间件 ---
app.use(cors());
app.use(express.json());

// --- 路由配置 ---
app.get('/lincyppq', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/index.css', (req, res) => res.sendFile(path.join(__dirname, 'index.css')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.get('/', (req, res) => res.status(403).send('Access Denied.'));

// --- 数据加载 ---
let botsDB = {};
if (fs.existsSync(DB_FILE)) {
    try { botsDB = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) {}
}
const saveDB = () => fs.writeFileSync(DB_FILE, JSON.stringify(botsDB, null, 2));

const activeConnections = new Map(); 

// --- WebSocket ---
wss.on('connection', (ws, req) => {
    const selfId = req.headers['x-self-id'] || req.headers['x-client-role'];
    
    if (selfId) {
        console.log(`NapCat 连接: ${selfId}`);
        activeConnections.set(String(selfId), ws);
        writeLog('BOT', 'CONNECTED', `Bot ${selfId} online`);
        
        if (!botsDB[selfId]) {
            botsDB[selfId] = { id: selfId, name: `Bot ${selfId}`, status: 'online', contracts: [] };
            saveDB();
        } else {
            botsDB[selfId].status = 'online';
        }
        
        ws.on('close', () => {
            activeConnections.delete(String(selfId));
            if (botsDB[selfId]) botsDB[selfId].status = 'offline';
            writeLog('BOT', 'DISCONNECTED', `Bot ${selfId} offline`);
        });

        ws.on('message', (message) => {
            try {
                const msg = JSON.parse(message);
                if (msg.post_type === 'message' && (msg.message_type === 'group' || (msg.message && msg.message_type === 'group'))) {
                    const rawText = msg.raw_message || msg.message || "";
                    const groupId = msg.group_id;
                    
                    if (rawText.startsWith('xa查询到期')) {
                        const botData = botsDB[selfId];
                        const contract = botData?.contracts?.find(c => String(c.groupId) === String(groupId));
                        let replyText = "";
                        if (!contract) {
                            replyText = "本群暂无授权记录或不在管理列表中。";
                        } else if (!contract.expireTime) {
                            replyText = "本群授权为永久有效。";
                        } else {
                            const diff = contract.expireTime - Date.now();
                            if (diff <= 0) {
                                replyText = "本群授权已过期，请及时续费。";
                            } else {
                                const days = Math.floor(diff / (1000 * 60 * 60 * 24));
                                const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
                                replyText = `剩余时间：${days}天 ${hours}小时`;
                            }
                        }
                        ws.send(JSON.stringify({ action: 'send_group_msg', params: { group_id: groupId, message: replyText } }));
                        writeLog('BOT', 'AUTO_REPLY_QUERY', `To Group ${groupId}: ${replyText}`);
                    }

                    if (rawText.startsWith('xa续费')) {
                        ws.send(JSON.stringify({ action: 'send_group_msg', params: { group_id: groupId, message: adminConfig.renewalMessage } }));
                        writeLog('BOT', 'AUTO_REPLY_RENEW', `To Group ${groupId}`);
                    }
                }
            } catch(e) {}
        });
    }
});

// --- Auth Middleware ---
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.sendStatus(401);
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// --- API Endpoints ---

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    
    if (username === adminConfig.username && password === adminConfig.password) {
        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '24h' });
        writeLog('USER', 'LOGIN', `User ${username} logged in`);
        recordLogin(username, ip, true);
        res.json({ token });
    } else {
        writeLog('USER', 'LOGIN_FAILED', `Failed attempt for ${username}`);
        recordLogin(username || 'unknown', ip, false);
        res.status(401).json({ error: 'Auth failed' });
    }
});

app.get('/api/admin/login-history', authenticateToken, (req, res) => {
    res.json(loginHistory);
});

app.post('/api/admin/change-password', authenticateToken, (req, res) => {
    const { newUsername, newPassword } = req.body;
    adminConfig.username = newUsername || adminConfig.username;
    adminConfig.password = newPassword || adminConfig.password;
    saveAdminConfig();
    writeLog('USER', 'UPDATE_AUTH', 'Admin credentials updated');
    res.json({ success: true });
});

app.get('/api/admin/config', authenticateToken, (req, res) => {
    res.json({
        defaultNotifyMessage: adminConfig.defaultNotifyMessage,
        warningDays: adminConfig.warningDays,
        warningMessage: adminConfig.warningMessage,
        renewalMessage: adminConfig.renewalMessage,
        backupRetentionDays: adminConfig.backupRetentionDays,
        autoQuit: adminConfig.autoQuit,
        quitWaitHours: adminConfig.quitWaitHours,
        quitMessage: adminConfig.quitMessage,
        uiTheme: adminConfig.uiTheme || { primaryColor: '#007AFF', backgroundImage: '', overlayOpacity: 0.4 }
    });
});

app.post('/api/admin/config', authenticateToken, (req, res) => {
    Object.assign(adminConfig, req.body);
    saveAdminConfig();
    writeLog('USER', 'UPDATE_CONFIG', 'Global config updated');
    res.json({ success: true });
});

app.get('/api/logs', authenticateToken, (req, res) => {
    res.json(logs);
});

app.post('/api/backup/now', authenticateToken, (req, res) => {
    performBackup();
    res.json({ success: true });
});

app.get('/api/bots', authenticateToken, (req, res) => {
    const list = Object.values(botsDB).map(bot => ({
        ...bot,
        isOnline: activeConnections.has(String(bot.id))
    }));
    res.json(list);
});

app.post('/api/bot/create', authenticateToken, (req, res) => {
    const { id, name } = req.body;
    if (botsDB[id]) return res.status(400).json({ error: 'Exists' });
    botsDB[id] = { id: String(id), name: name || `Bot ${id}`, status: 'offline', contracts: [] };
    saveDB();
    writeLog('USER', 'ADD_BOT', `Added bot ${id}`);
    res.json({ success: true });
});

app.post('/api/bot/update-info', authenticateToken, (req, res) => {
    const { id, name, avatar } = req.body;
    if (botsDB[id]) {
        botsDB[id].name = name;
        if (avatar !== undefined) botsDB[id].avatar = avatar;
        saveDB();
        res.json({ success: true });
    } else res.status(404).json({ error: 'Not Found' });
});

app.post('/api/bot/contract/save', authenticateToken, (req, res) => {
    const { botId, contractId, groupId, expireTime } = req.body;
    if (!botsDB[botId]) return res.status(404).json({ error: 'Not Found' });
    
    let contract = botsDB[botId].contracts.find(c => c.id === contractId);
    if (contract) {
        // 如果续期了（时间比之前晚），则重置通知状态和退群状态
        if (expireTime > (contract.expireTime || 0)) {
            contract.notified = false; 
            contract.preNotified = false;
            contract.leftGroup = false; // 重置退群标记
        }
        contract.groupId = groupId;
        contract.expireTime = expireTime;
        writeLog('USER', 'UPDATE_CONTRACT', `Updated contract for Group ${groupId}`);
    } else {
        contract = {
            id: Date.now().toString(36) + Math.random().toString(36).substr(2),
            groupId,
            expireTime,
            notified: false,
            preNotified: false,
            leftGroup: false
        };
        botsDB[botId].contracts.push(contract);
        writeLog('USER', 'ADD_CONTRACT', `Added contract for Group ${groupId}`);
    }
    saveDB();
    res.json({ success: true });
});

app.post('/api/bot/contract/delete', authenticateToken, (req, res) => {
    const { botId, contractId } = req.body;
    if (botsDB[botId]) {
        botsDB[botId].contracts = botsDB[botId].contracts.filter(c => c.id !== contractId);
        saveDB();
        writeLog('USER', 'DELETE_CONTRACT', `Deleted contract ${contractId}`);
        res.json({ success: true });
    } else res.status(404).json({ error: 'Not Found' });
});

// 新增：手动退群接口
app.post('/api/bot/quit-group', authenticateToken, (req, res) => {
    const { botId, groupId } = req.body;
    const ws = activeConnections.get(String(botId));
    
    if (ws && ws.readyState === WebSocket.OPEN) {
        // 1. 发送退群指令
        ws.send(JSON.stringify({ action: 'set_group_leave', params: { group_id: parseInt(groupId) } }));
        
        // 2. 更新数据库状态
        if (botsDB[botId]) {
            const contract = botsDB[botId].contracts.find(c => String(c.groupId) === String(groupId));
            if (contract) {
                contract.leftGroup = true;
                saveDB();
            }
        }
        
        writeLog('USER', 'MANUAL_QUIT', `Manually quit group ${groupId}`);
        res.json({ success: true });
    } else {
        res.status(500).json({ error: 'Bot Offline' });
    }
});

app.post('/api/bot/delete', authenticateToken, (req, res) => {
    const { id } = req.body;
    delete botsDB[id];
    saveDB();
    writeLog('USER', 'DELETE_BOT', `Deleted bot ${id}`);
    res.json({ success: true });
});

app.post('/api/bot/send', authenticateToken, (req, res) => {
    const { id, group_id, message } = req.body;
    const ws = activeConnections.get(String(id));
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
            action: 'send_group_msg',
            params: { group_id: parseInt(group_id), message }
        }));
        writeLog('USER', 'SEND_MSG', `Manual msg to Group ${group_id}`);
        res.json({ success: true });
    } else res.status(500).json({ error: 'Bot Offline' });
});

app.post('/api/upload', authenticateToken, upload.single('image'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file' });
    res.json({ 
        path: path.resolve(req.file.path),
        url: `/uploads/${req.file.filename}` 
    });
});

// --- 定时任务 ---
cron.schedule('* * * * *', () => {
    const now = Date.now();
    let changed = false;
    const notifyMsg = adminConfig.defaultNotifyMessage;
    const warnMsg = adminConfig.warningMessage;
    const warnTime = (adminConfig.warningDays || 3) * 24 * 60 * 60 * 1000;
    const quitWaitTime = (adminConfig.quitWaitHours || 24) * 60 * 60 * 1000;

    Object.values(botsDB).forEach(bot => {
        const ws = activeConnections.get(String(bot.id));
        const isOnline = ws && ws.readyState === WebSocket.OPEN;

        bot.contracts.forEach(c => {
            if (!c.expireTime) return;
            
            // 1. 预警逻辑
            if (!c.preNotified && !c.notified && (c.expireTime - now < warnTime) && (c.expireTime > now)) {
                if (isOnline) {
                    ws.send(JSON.stringify({ action: 'send_group_msg', params: { group_id: parseInt(c.groupId), message: warnMsg } }));
                    writeLog('SYSTEM', 'WARN_SENT', `Warning sent to Group ${c.groupId}`);
                    c.preNotified = true;
                    changed = true;
                }
            }

            // 2. 到期通知逻辑
            if (!c.notified && now > c.expireTime) {
                if (isOnline) {
                    ws.send(JSON.stringify({ action: 'send_group_msg', params: { group_id: parseInt(c.groupId), message: notifyMsg } }));
                    writeLog('SYSTEM', 'EXPIRE_SENT', `Expiry sent to Group ${c.groupId}`);
                    c.notified = true;
                    changed = true;
                }
            }

            // 3. 自动退群逻辑
            if (adminConfig.autoQuit && !c.leftGroup && now > (c.expireTime + quitWaitTime)) {
                if (isOnline) {
                    // 先发告别
                    ws.send(JSON.stringify({ action: 'send_group_msg', params: { group_id: parseInt(c.groupId), message: adminConfig.quitMessage } }));
                    
                    // 延迟退群，防止消息没发出去
                    setTimeout(() => {
                        if (activeConnections.get(String(bot.id))) { // Double check connection
                             ws.send(JSON.stringify({ action: 'set_group_leave', params: { group_id: parseInt(c.groupId) } }));
                        }
                    }, 2000);

                    writeLog('SYSTEM', 'AUTO_QUIT', `Bot left Group ${c.groupId} due to expiry`);
                    c.leftGroup = true;
                    changed = true;
                }
            }
        });
    });
    if (changed) saveDB();
});

cron.schedule('0 3 * * *', () => {
    performBackup();
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`NapCat Admin Panel: http://localhost:${PORT}/lincyppq`);
});
