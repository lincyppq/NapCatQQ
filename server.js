
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

// --- Configuration ---
const PORT = 54321;
const JWT_SECRET = 'napcat-secret-key-change-this'; // Please change this in production
const DB_FILE = path.join(__dirname, 'bots.json');
const ADMIN_FILE = path.join(__dirname, 'admin.json');
const AUDIT_FILE = path.join(__dirname, 'audit.json');
const LOGIN_HISTORY_FILE = path.join(__dirname, 'login_history.json');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const BACKUPS_DIR = path.join(__dirname, 'backups');

// --- Directory Initialization ---
[UPLOADS_DIR, BACKUPS_DIR].forEach(dir => {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir);
});

// --- Multer Config ---
const storage = multer.diskStorage({
    destination: function (req, file, cb) { cb(null, UPLOADS_DIR) },
    filename: function (req, file, cb) {
        const ext = path.extname(file.originalname);
        cb(null, Date.now() + ext);
    }
});
const upload = multer({ storage: storage });

// --- Initial Data ---
let adminConfig = {
    username: 'admin',
    password: 'admin123',
    defaultNotifyMessage: '[系统通知] 本群机器人服务已到期，请联系管理员续费。',
    warningDays: 3,
    warningMessage: '[温馨提醒] 本群机器人服务即将到期，请及时续费以免影响使用。',
    renewalMessage: '请联系管理员进行续费。\n支持微信/支付宝。',
    backupRetentionDays: 7,
    // Auto Quit Strategy
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
    } catch (e) { console.error("Failed to read admin config"); }
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

// --- Security: Rate Limiting ---
const loginAttempts = new Map(); // IP -> { count, blockedUntil }

const checkRateLimit = (ip) => {
    const now = Date.now();
    const record = loginAttempts.get(ip);
    if (!record) return true;
    if (record.blockedUntil && now < record.blockedUntil) return false;
    return true;
};

const recordLoginAttempt = (ip, success) => {
    const now = Date.now();
    let record = loginAttempts.get(ip) || { count: 0, blockedUntil: 0 };
    
    if (success) {
        loginAttempts.delete(ip); // Reset on success
    } else {
        // If previously blocked and time passed, reset
        if (record.blockedUntil && now > record.blockedUntil) {
            record = { count: 0, blockedUntil: 0 };
        }
        
        record.count += 1;
        if (record.count >= 5) {
            record.blockedUntil = now + 15 * 60 * 1000; // Block for 15 minutes
            console.warn(`IP ${ip} blocked due to too many failed login attempts.`);
        }
        loginAttempts.set(ip, record);
    }
};

// --- Logging System ---
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

// --- Login History ---
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

// --- Backup System ---
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

// --- Middleware ---
app.use(cors());
app.use(express.json());

// --- Routes ---
app.get('/lincyppq', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/index.css', (req, res) => res.sendFile(path.join(__dirname, 'index.css')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.get('/', (req, res) => res.status(403).send('Access Denied.'));

// --- DB Loading ---
let botsDB = {};
if (fs.existsSync(DB_FILE)) {
    try { botsDB = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) {}
}
const saveDB = () => fs.writeFileSync(DB_FILE, JSON.stringify(botsDB, null, 2));

const activeConnections = new Map(); 
const pendingRequests = new Map();

// --- WebSocket ---
wss.on('connection', (ws, req) => {
    const selfId = req.headers['x-self-id'] || req.headers['x-client-role'];
    
    if (selfId) {
        console.log(`NapCat Connected: ${selfId}`);
        activeConnections.set(String(selfId), ws);
        writeLog('BOT', 'CONNECTED', `Bot ${selfId} online`);
        
        if (!botsDB[selfId]) {
            botsDB[selfId] = { id: selfId, name: `Bot ${selfId}`, status: 'online', contracts: [] };
            saveDB();
        } else {
            botsDB[selfId].status = 'online';
            // Restore if deleted but reconnected? No, keep it deleted until manually restored.
        }
        
        ws.on('close', () => {
            activeConnections.delete(String(selfId));
            if (botsDB[selfId]) botsDB[selfId].status = 'offline';
            writeLog('BOT', 'DISCONNECTED', `Bot ${selfId} offline`);
        });

        ws.on('message', (message) => {
            try {
                const msg = JSON.parse(message);

                // Echo mechanism for sync requests
                if (msg.echo && pendingRequests.has(msg.echo)) {
                    const { resolve } = pendingRequests.get(msg.echo);
                    resolve(msg);
                    pendingRequests.delete(msg.echo);
                    return; 
                }

                // Auto Reply Logic
                if (msg.post_type === 'message' && (msg.message_type === 'group' || (msg.message && msg.message_type === 'group'))) {
                    const rawText = msg.raw_message || msg.message || "";
                    const groupId = msg.group_id;
                    
                    if (rawText.startsWith('xa查询到期')) {
                        const botData = botsDB[selfId];
                        if (botData.deleted) return; // Ignore deleted bots

                        const contract = botData?.contracts?.find(c => String(c.groupId) === String(groupId) && !c.deleted);
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
    const cleanIp = ip.replace(/^::ffff:/, '');

    // Rate Limiting Check
    if (!checkRateLimit(cleanIp)) {
        return res.status(429).json({ error: '尝试次数过多，IP 已暂时锁定 15 分钟' });
    }
    
    if (username === adminConfig.username && password === adminConfig.password) {
        recordLoginAttempt(cleanIp, true);
        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '24h' });
        writeLog('USER', 'LOGIN', `User ${username} logged in`);
        recordLogin(username, ip, true);
        res.json({ token });
    } else {
        recordLoginAttempt(cleanIp, false);
        writeLog('USER', 'LOGIN_FAILED', `Failed attempt for ${username} from ${cleanIp}`);
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

// Test Message Endpoint (Template Testing)
app.post('/api/admin/test-msg', authenticateToken, (req, res) => {
    const { targetGroup, msgType } = req.body; 
    
    let message = '';
    if (msgType === 'renewal') message = adminConfig.renewalMessage;
    else if (msgType === 'expire') message = adminConfig.defaultNotifyMessage;
    else if (msgType === 'warning') message = adminConfig.warningMessage;
    else if (msgType === 'quit') message = adminConfig.quitMessage;
    else return res.status(400).json({ error: 'Unknown message type' });

    const onlineBotId = Object.keys(botsDB).find(id => activeConnections.has(id) && !botsDB[id].deleted);
    if (!onlineBotId) return res.status(503).json({ error: '没有在线的机器人实例可用于发送测试消息' });

    const ws = activeConnections.get(onlineBotId);
    ws.send(JSON.stringify({
        action: 'send_group_msg',
        params: { group_id: parseInt(targetGroup), message }
    }));

    res.json({ success: true, botUsed: onlineBotId });
});

app.get('/api/logs', authenticateToken, (req, res) => {
    res.json(logs);
});

app.post('/api/backup/now', authenticateToken, (req, res) => {
    performBackup();
    res.json({ success: true });
});

// Get active bots (exclude deleted)
app.get('/api/bots', authenticateToken, (req, res) => {
    const list = Object.values(botsDB)
        .filter(bot => !bot.deleted) // Filter out soft-deleted bots
        .map(bot => ({
            ...bot,
            // Filter out soft-deleted contracts for the frontend
            contracts: (bot.contracts || []).filter(c => !c.deleted),
            isOnline: activeConnections.has(String(bot.id))
        }));
    res.json(list);
});

app.post('/api/bot/create', authenticateToken, (req, res) => {
    const { id, name } = req.body;
    if (botsDB[id]) {
        if (botsDB[id].deleted) {
            // If exists but deleted, restore it
            botsDB[id].deleted = false;
            botsDB[id].name = name || botsDB[id].name;
            saveDB();
            writeLog('USER', 'RESTORE_BOT', `Restored bot ${id} via create`);
            return res.json({ success: true });
        }
        return res.status(400).json({ error: 'Exists' });
    }
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

app.post('/api/bot/group-info', authenticateToken, async (req, res) => {
    const { botId, groupId } = req.body;
    const ws = activeConnections.get(String(botId));
    
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        return res.status(500).json({ error: 'Bot Offline' });
    }

    const echo = Date.now().toString(36) + Math.random().toString(36).substr(2);
    
    const responsePromise = new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
            pendingRequests.delete(echo);
            reject(new Error('Timeout waiting for bot response'));
        }, 5000); 

        pendingRequests.set(echo, {
            resolve: (data) => {
                clearTimeout(timeout);
                resolve(data);
            },
            reject
        });
    });

    ws.send(JSON.stringify({
        action: 'get_group_info',
        params: { group_id: parseInt(groupId), no_cache: true },
        echo
    }));

    try {
        const data = await responsePromise;
        if (data.status === 'ok' && data.data) {
            res.json({ 
                groupName: data.data.group_name,
                memberCount: data.data.member_count
            });
        } else {
            res.status(400).json({ error: 'Failed to get group info' });
        }
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/bot/group-list', authenticateToken, async (req, res) => {
    const { botId } = req.body;
    const ws = activeConnections.get(String(botId));

    if (!ws || ws.readyState !== WebSocket.OPEN) {
        return res.status(500).json({ error: 'Bot Offline' });
    }

    const echo = Date.now().toString(36) + Math.random().toString(36).substr(2);
    
    const responsePromise = new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
            pendingRequests.delete(echo);
            reject(new Error('Timeout waiting for bot response'));
        }, 5000); 

        pendingRequests.set(echo, {
            resolve: (data) => {
                clearTimeout(timeout);
                resolve(data);
            },
            reject
        });
    });

    ws.send(JSON.stringify({
        action: 'get_group_list',
        echo
    }));

    try {
        const data = await responsePromise;
        if (data.status === 'ok' && Array.isArray(data.data)) {
            res.json(data.data); 
        } else {
            res.status(400).json({ error: 'Failed to get group list' });
        }
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/bot/contract/save', authenticateToken, (req, res) => {
    const { botId, contractId, groupId, groupName, expireTime } = req.body;
    if (!botsDB[botId]) return res.status(404).json({ error: 'Not Found' });
    
    let contract = botsDB[botId].contracts.find(c => c.id === contractId);
    if (contract) {
        // If un-deleted during save, handle that? Usually save is on active.
        if (expireTime > (contract.expireTime || 0)) {
            contract.notified = false; 
            contract.preNotified = false;
            contract.leftGroup = false;
        }
        contract.groupId = groupId;
        contract.expireTime = expireTime;
        if (groupName) contract.groupName = groupName;
        writeLog('USER', 'UPDATE_CONTRACT', `Updated contract for Group ${groupId} (${groupName||''})`);
    } else {
        contract = {
            id: Date.now().toString(36) + Math.random().toString(36).substr(2),
            groupId,
            groupName: groupName || `群 ${groupId}`,
            expireTime,
            notified: false,
            preNotified: false,
            leftGroup: false
        };
        botsDB[botId].contracts.push(contract);
        writeLog('USER', 'ADD_CONTRACT', `Added contract for Group ${groupId} (${groupName||''})`);
    }
    saveDB();
    res.json({ success: true });
});

// Soft Delete Contract
app.post('/api/bot/contract/delete', authenticateToken, (req, res) => {
    const { botId, contractId } = req.body;
    if (botsDB[botId]) {
        const contract = botsDB[botId].contracts.find(c => c.id === contractId);
        if (contract) {
            contract.deleted = true;
            contract.deletedAt = Date.now();
            saveDB();
            writeLog('USER', 'DELETE_CONTRACT', `Soft deleted contract ${contractId}`);
            res.json({ success: true });
        } else res.status(404).json({ error: 'Contract Not Found' });
    } else res.status(404).json({ error: 'Bot Not Found' });
});

app.post('/api/bot/quit-group', authenticateToken, (req, res) => {
    const { botId, groupId } = req.body;
    const ws = activeConnections.get(String(botId));
    
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ action: 'set_group_leave', params: { group_id: parseInt(groupId) } }));
        
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

// Soft Delete Bot
app.post('/api/bot/delete', authenticateToken, (req, res) => {
    const { id } = req.body;
    if (botsDB[id]) {
        botsDB[id].deleted = true;
        botsDB[id].deletedAt = Date.now();
        saveDB();
        writeLog('USER', 'DELETE_BOT', `Soft deleted bot ${id}`);
        res.json({ success: true });
    } else res.status(404).json({ error: 'Not Found' });
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

// --- Recycle Bin Endpoints ---
app.get('/api/recycle-bin', authenticateToken, (req, res) => {
    const deletedBots = Object.values(botsDB).filter(b => b.deleted);
    // Find deleted contracts from active bots (or all bots? let's do active bots to avoid confusion if bot is deleted)
    // Strategy: Just list deleted contracts from ALL bots.
    let deletedContracts = [];
    Object.values(botsDB).forEach(bot => {
        if (bot.contracts) {
            bot.contracts.forEach(c => {
                if (c.deleted) {
                    deletedContracts.push({
                        ...c,
                        botId: bot.id,
                        botName: bot.name
                    });
                }
            });
        }
    });
    
    res.json({ bots: deletedBots, contracts: deletedContracts });
});

app.post('/api/recycle-bin/restore', authenticateToken, (req, res) => {
    const { type, id, botId } = req.body; // type: 'bot' or 'contract'
    
    if (type === 'bot') {
        if (botsDB[id]) {
            botsDB[id].deleted = false;
            delete botsDB[id].deletedAt;
            saveDB();
            writeLog('USER', 'RESTORE', `Restored bot ${id}`);
            res.json({ success: true });
        } else res.status(404).json({error: 'Not found'});
    } else if (type === 'contract') {
        if (botsDB[botId]) {
            const c = botsDB[botId].contracts.find(c => c.id === id);
            if (c) {
                c.deleted = false;
                delete c.deletedAt;
                saveDB();
                writeLog('USER', 'RESTORE', `Restored contract ${id}`);
                res.json({ success: true });
            } else res.status(404).json({error: 'Not found'});
        } else res.status(404).json({error: 'Bot not found'});
    } else {
        res.status(400).json({error: 'Invalid type'});
    }
});

app.post('/api/recycle-bin/purge', authenticateToken, (req, res) => {
    const { type, id, botId } = req.body;
    
    if (type === 'bot') {
        if (botsDB[id]) {
            delete botsDB[id];
            saveDB();
            writeLog('USER', 'PURGE', `Permanently deleted bot ${id}`);
            res.json({ success: true });
        } else res.status(404).json({error: 'Not found'});
    } else if (type === 'contract') {
        if (botsDB[botId]) {
            botsDB[botId].contracts = botsDB[botId].contracts.filter(c => c.id !== id);
            saveDB();
            writeLog('USER', 'PURGE', `Permanently deleted contract ${id}`);
            res.json({ success: true });
        } else res.status(404).json({error: 'Bot not found'});
    } else {
        res.status(400).json({error: 'Invalid type'});
    }
});

// --- Cron Jobs ---
cron.schedule('* * * * *', () => {
    const now = Date.now();
    let changed = false;
    const notifyMsg = adminConfig.defaultNotifyMessage;
    const warnMsg = adminConfig.warningMessage;
    const warnTime = (adminConfig.warningDays || 3) * 24 * 60 * 60 * 1000;
    const quitWaitTime = (adminConfig.quitWaitHours || 24) * 60 * 60 * 1000;

    Object.values(botsDB).forEach(bot => {
        if (bot.deleted) return; // Skip deleted bots

        const ws = activeConnections.get(String(bot.id));
        const isOnline = ws && ws.readyState === WebSocket.OPEN;

        bot.contracts.forEach(c => {
            if (c.deleted) return; // Skip deleted contracts
            if (!c.expireTime) return;
            
            // Pre-warning
            if (!c.preNotified && !c.notified && (c.expireTime - now < warnTime) && (c.expireTime > now)) {
                if (isOnline) {
                    ws.send(JSON.stringify({ action: 'send_group_msg', params: { group_id: parseInt(c.groupId), message: warnMsg } }));
                    writeLog('SYSTEM', 'WARN_SENT', `Warning sent to Group ${c.groupId}`);
                    c.preNotified = true;
                    changed = true;
                }
            }

            // Expiry
            if (!c.notified && now > c.expireTime) {
                if (isOnline) {
                    ws.send(JSON.stringify({ action: 'send_group_msg', params: { group_id: parseInt(c.groupId), message: notifyMsg } }));
                    writeLog('SYSTEM', 'EXPIRE_SENT', `Expiry sent to Group ${c.groupId}`);
                    c.notified = true;
                    changed = true;
                }
            }

            // Auto Quit
            if (adminConfig.autoQuit && !c.leftGroup && now > (c.expireTime + quitWaitTime)) {
                if (isOnline) {
                    ws.send(JSON.stringify({ action: 'send_group_msg', params: { group_id: parseInt(c.groupId), message: adminConfig.quitMessage } }));
                    
                    setTimeout(() => {
                        if (activeConnections.get(String(bot.id))) { 
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
    
    // Auto-purge recycle bin (> 7 days)
    const now = Date.now();
    const sevenDays = 7 * 24 * 60 * 60 * 1000;
    let dbChanged = false;
    
    // Purge bots
    const botIds = Object.keys(botsDB);
    botIds.forEach(id => {
        if (botsDB[id].deleted && (now - botsDB[id].deletedAt > sevenDays)) {
            delete botsDB[id];
            dbChanged = true;
            console.log(`Auto purged bot ${id}`);
        } else {
            // Purge contracts
            if (botsDB[id].contracts) {
                const originalLen = botsDB[id].contracts.length;
                botsDB[id].contracts = botsDB[id].contracts.filter(c => 
                    !c.deleted || (now - c.deletedAt <= sevenDays)
                );
                if (botsDB[id].contracts.length !== originalLen) dbChanged = true;
            }
        }
    });
    
    if (dbChanged) saveDB();
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`NapCat Admin Panel: http://localhost:${PORT}/lincyppq`);
});
