const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const cron = require('node-cron');
const multer = require('multer');
const axios = require('axios');
const nodemailer = require('nodemailer');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// --- Configuration ---
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 23333;
const JWT_SECRET_FILE = path.join(__dirname, 'jwt_secret.txt');
let JWT_SECRET = process.env.JWT_SECRET || '';
const DB_FILE = path.join(__dirname, 'bots.json');
const ADMIN_FILE = path.join(__dirname, 'admin.json');
const AUDIT_FILE = path.join(__dirname, 'audit.json');
const LOGIN_HISTORY_FILE = path.join(__dirname, 'login_history.json');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const BACKUPS_DIR = path.join(__dirname, 'backups');
const WS_TOKEN = process.env.WS_TOKEN || '';
const MAX_IMAGE_BYTES = process.env.MAX_IMAGE_BYTES ? parseInt(process.env.MAX_IMAGE_BYTES, 10) : 5 * 1024 * 1024;
const MAX_BACKUP_BYTES = process.env.MAX_BACKUP_BYTES ? parseInt(process.env.MAX_BACKUP_BYTES, 10) : 2 * 1024 * 1024;
const WS_HEARTBEAT_INTERVAL_MS = process.env.WS_HEARTBEAT_INTERVAL_MS ? parseInt(process.env.WS_HEARTBEAT_INTERVAL_MS, 10) : 30000;
const WS_OFFLINE_AFTER_MS = process.env.WS_OFFLINE_AFTER_MS ? parseInt(process.env.WS_OFFLINE_AFTER_MS, 10) : 65000;
const TRUST_PROXY = process.env.TRUST_PROXY === '1' || process.env.TRUST_PROXY === 'true';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map(o => o.trim())
    .filter(Boolean);
const DEFAULT_ALLOWED_ORIGINS = [`http://localhost:${PORT}`, `http://127.0.0.1:${PORT}`];

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
const uploadImage = multer({
    storage: storage,
    limits: { fileSize: MAX_IMAGE_BYTES },
    fileFilter: (req, file, cb) => {
        const allowed = ['image/png', 'image/jpeg', 'image/gif', 'image/webp'];
        if (allowed.includes(file.mimetype)) return cb(null, true);
        cb(new Error('Invalid image type'));
    }
});
const uploadBackup = multer({
    storage: storage,
    limits: { fileSize: MAX_BACKUP_BYTES },
    fileFilter: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        const allowed = ['application/json', 'text/plain'];
        if (ext === '.json' || allowed.includes(file.mimetype)) return cb(null, true);
        cb(new Error('Invalid backup file'));
    }
});

// --- Initial Data ---
let adminConfig = {
    username: 'admin',
    passwordHash: '',
    defaultNotifyMessage: '[系统通知] 本群机器人服务已到期，请联系管理员续费。',
    warningDays: 3,
    warningMessage: '[温馨提醒] 本群机器人服务即将到期，请及时续费以免影响使用。',
    renewalMessage: '请联系管理员进行续费。\n支持微信/支付宝。',
    backupRetentionDays: 7,
    // Auto Quit Strategy
    autoQuit: false,
    quitWaitHours: 24,
    quitMessage: '[服务结束] 由于服务到期未续费，机器人将自动退出本群。感谢使用，江湖再见。',
    // Custom Commands
    cmdPrefix: 'xa',
    cmdQuery: '查询到期',
    cmdRenew: '续费',
    // Command Expire Notice
    commandExpireNoticeCooldown: 30, // 指令触发到期提醒的冷却时间（分钟）
    // Auto Handle Group Invite
    autoHandleGroupInvite: true, // 自动处理加群邀请
    uiTheme: {
        primaryColor: '#007AFF',
        backgroundImage: '',
        overlayOpacity: 0.4
    },
    // Email Notification
    emailNotification: {
        enabled: false,
        smtpHost: 'smtp.qq.com',
        smtpPort: 465,
        smtpSecure: true,
        smtpUser: '',
        smtpPass: '',
        recipientEmail: ''
    }
};

let logs = [];
let loginHistory = [];
const offlineNotificationCache = new Map(); // Track last notification time for each bot

if (fs.existsSync(ADMIN_FILE)) {
    try {
        const savedConfig = JSON.parse(fs.readFileSync(ADMIN_FILE, 'utf8'));
        adminConfig = { ...adminConfig, ...savedConfig };
        if (!adminConfig.uiTheme) adminConfig.uiTheme = { primaryColor: '#007AFF', backgroundImage: '', overlayOpacity: 0.4 };
        // Remove obsolete fields
        delete adminConfig.monitorPorts;
        delete adminConfig.blacklist;
    } catch (e) { console.error("Failed to read admin config"); }
} else {
    adminConfig.passwordHash = bcrypt.hashSync('admin123', 10);
    fs.writeFileSync(ADMIN_FILE, JSON.stringify(adminConfig, null, 2));
}

if (fs.existsSync(AUDIT_FILE)) {
    try { logs = JSON.parse(fs.readFileSync(AUDIT_FILE, 'utf8')); } catch (e) { }
}

if (fs.existsSync(LOGIN_HISTORY_FILE)) {
    try { loginHistory = JSON.parse(fs.readFileSync(LOGIN_HISTORY_FILE, 'utf8')); } catch (e) { }
}

const fileWriteQueues = new Map();
const genId = () => Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
const defaultBotAvatar = (id) => `https://q1.qlogo.cn/g?b=qq&nk=${id}&s=100`;
const normalizeBotAvatar = (id, avatar) => {
    const value = String(avatar || '').trim();
    if (!value) return defaultBotAvatar(id);
    if (value.startsWith('http') || value.startsWith('/')) return value;
    if (/^\d+$/.test(value)) return defaultBotAvatar(value);
    return value;
};
const normalizeContract = (contract) => {
    if (!contract) return null;
    const groupId = contract.groupId !== undefined ? String(contract.groupId) : '';
    return {
        ...contract,
        id: contract.id || genId(),
        groupId,
        groupName: contract.groupName || (groupId ? `群${groupId}` : ''),
        expireTime: typeof contract.expireTime === 'number' ? contract.expireTime : null,
        deleted: Boolean(contract.deleted),
        leftGroup: Boolean(contract.leftGroup),
        notified: Boolean(contract.notified),
        preNotified: Boolean(contract.preNotified),
        lastDaysAdded: typeof contract.lastDaysAdded === 'number' ? contract.lastDaysAdded : null,
        daysAddedAt: typeof contract.daysAddedAt === 'number' ? contract.daysAddedAt : null,
        lastCommandExpireNoticeAt: typeof contract.lastCommandExpireNoticeAt === 'number' ? contract.lastCommandExpireNoticeAt : null
    };
};
const normalizeBot = (bot) => {
    if (!bot) return null;
    const id = bot.id !== undefined ? String(bot.id) : '';
    if (!id) return null;
    return {
        ...bot,
        id,
        name: bot.name || `Bot ${id}`,
        avatar: normalizeBotAvatar(id, bot.avatar),
        lastSeen: typeof bot.lastSeen === 'number' ? bot.lastSeen : 0,
        pausedAt: typeof bot.pausedAt === 'number' ? bot.pausedAt : null,
        contracts: Array.isArray(bot.contracts) ? bot.contracts.map(normalizeContract).filter(Boolean) : []
    };
};
const normalizeBotsDB = (db) => {
    const next = {};
    Object.keys(db || {}).forEach(key => {
        const normalized = normalizeBot(db[key]);
        if (normalized) next[normalized.id] = normalized;
    });
    return next;
};
const queueWrite = (filePath, data) => {
    const payload = JSON.stringify(data, null, 2);
    const prev = fileWriteQueues.get(filePath) || Promise.resolve();
    const next = prev
        .catch(() => { })
        .then(() => fs.promises.writeFile(filePath, payload))
        .catch(() => { });
    fileWriteQueues.set(filePath, next);
};

const saveAdminConfig = () => queueWrite(ADMIN_FILE, adminConfig);

// --- 鸣潮功能指令识别函数 ---
const isWutheringWavesCommand = (rawText, prefix, queryCmd, renewCmd) => {
    const trimmed = rawText.trim();
    if (!trimmed.startsWith(prefix)) return false;

    // 排除查询到期和续费命令
    if (trimmed.startsWith(queryCmd) || trimmed.startsWith(renewCmd)) return false;

    // 去掉前缀，得到命令主体
    const commandBody = trimmed.substring(prefix.length);
    if (!commandBody) return false;

    // 精确匹配的常用命令
    const exactCommands = [
        '登录', '绑定', '绑定特征码', '切换特征码', '查看特征码', '获取token', '添加token',
        '卡片', '练度统计', '体力', '日历', '兑换码',
        '深塔', '深塔战略', '深塔出场率', '冥歌海墟', '矩阵',
        '签到', '签到日历', '开启自动签到', '推送邮箱', '开启推送', '推送阈值',
        '帮助', '菜单', '指令'
    ];
    if (exactCommands.includes(commandBody)) return true;

    // 前缀匹配的命令类型
    const prefixCommands = [
        '抽卡', '角色', '武器', '声骸', '公告', '推送', '绑定', '深塔', '矩阵', '冥歌'
    ];
    if (prefixCommands.some(cmd => commandBody.startsWith(cmd))) return true;

    // 包含或结尾匹配
    if (commandBody.includes('面板') || commandBody.endsWith('面板')) return true;
    if (commandBody.includes('排行') || commandBody.endsWith('排行')) return true;

    return false;
};

if (adminConfig.password && !adminConfig.passwordHash) {
    adminConfig.passwordHash = bcrypt.hashSync(adminConfig.password, 10);
    delete adminConfig.password;
    saveAdminConfig();
}

// --- Security: Rate Limiting ---
const loginAttempts = new Map();

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
        loginAttempts.delete(ip);
    } else {
        if (record.blockedUntil && now > record.blockedUntil) record = { count: 0, blockedUntil: 0 };
        record.count += 1;
        if (record.count >= 5) {
            record.blockedUntil = now + 15 * 60 * 1000;
            console.warn(`IP ${ip} blocked due to too many failed login attempts.`);
        }
        loginAttempts.set(ip, record);
    }
};

// --- Logging System ---
const writeLog = (type, action, details) => {
    const entry = {
        id: genId(),
        time: Date.now(),
        type,
        action,
        details
    };
    logs.unshift(entry);
    if (logs.length > 500) logs = logs.slice(0, 500);
    queueWrite(AUDIT_FILE, logs);
};

// --- Login History ---
const getIpLocation = async (ip) => {
    if (!ip || ip === '::1' || ip === '127.0.0.1' || ip.startsWith('192.168')) return '本地/局域网';
    try {
        const res = await axios.get(`http://ip-api.com/json/${ip}?lang=zh-CN`, { timeout: 3000 });
        if (res.data.status === 'success') return `${res.data.country} ${res.data.regionName} ${res.data.city}`;
        return '未知位置';
    } catch (e) { return '查询失败'; }
};

const recordLogin = async (username, ip, success) => {
    const cleanIp = ip.replace(/^::ffff:/, '');
    const entry = {
        id: genId(),
        time: Date.now(),
        username,
        ip: cleanIp,
        location: '查询中...',
        status: success
    };
    loginHistory.unshift(entry);
    if (loginHistory.length > 200) loginHistory = loginHistory.slice(0, 200);
    queueWrite(LOGIN_HISTORY_FILE, loginHistory);
    try {
        const location = await getIpLocation(cleanIp);
        entry.location = location;
        queueWrite(LOGIN_HISTORY_FILE, loginHistory);
    } catch (e) { }
};

// --- Backup System ---
const performBackup = () => {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupPath = path.join(BACKUPS_DIR, `backup-${timestamp}`);
    try {
        if (fs.existsSync(DB_FILE)) fs.copyFileSync(DB_FILE, `${backupPath}-bots.json`);
        if (fs.existsSync(ADMIN_FILE)) fs.copyFileSync(ADMIN_FILE, `${backupPath}-admin.json`);
        writeLog('SYSTEM', '创建备份', `自动备份成功: ${timestamp}`);

        const retentionMs = (adminConfig.backupRetentionDays || 7) * 24 * 60 * 60 * 1000;
        const files = fs.readdirSync(BACKUPS_DIR);
        const now = Date.now();
        files.forEach(file => {
            const filePath = path.join(BACKUPS_DIR, file);
            const stats = fs.statSync(filePath);
            if (now - stats.mtimeMs > retentionMs) fs.unlinkSync(filePath);
        });
    } catch (e) { writeLog('SYSTEM', '备份失败', `备份出错: ${e.message}`); }
};

// --- Email Notification System ---
const sendOfflineEmail = async (botId, botName, reason = '连接断开') => {
    try {
        const emailConfig = adminConfig.emailNotification;

        // Check if email notification is enabled and configured
        if (!emailConfig.enabled) return;
        if (!emailConfig.smtpUser || !emailConfig.smtpPass || !emailConfig.recipientEmail) {
            console.warn('Email notification enabled but not fully configured');
            return;
        }

        // Create transporter
        const transporter = nodemailer.createTransport({
            host: emailConfig.smtpHost,
            port: emailConfig.smtpPort,
            secure: emailConfig.smtpSecure,
            auth: {
                user: emailConfig.smtpUser,
                pass: emailConfig.smtpPass
            }
        });

        // Format timestamp
        const now = new Date();
        const timeStr = now.toLocaleString('zh-CN', {
            timeZone: 'Asia/Shanghai',
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });

        // Email content
        const mailOptions = {
            from: `\"NapCat 监控系统\" <${emailConfig.smtpUser}>`,
            to: emailConfig.recipientEmail,
            subject: `⚠️ 机器人掉线通知 - ${botName || botId}`,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f5f5f5;">
                    <div style="background-color: #fff; border-radius: 8px; padding: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                        <h2 style="color: #ff4444; margin-top: 0;">⚠️ 机器人掉线通知</h2>
                        <div style="background-color: #fff3cd; border-left: 4px solid #ff9800; padding: 15px; margin: 20px 0;">
                            <p style="margin: 5px 0;"><strong>机器人账号：</strong>${botId}</p>
                            <p style="margin: 5px 0;"><strong>机器人名称：</strong>${botName || '未设置'}</p>
                            <p style="margin: 5px 0;"><strong>故障原因：</strong>${reason}</p>
                            <p style="margin: 5px 0;"><strong>检测时间：</strong>${timeStr}</p>
                        </div>
                        <p style="color: #666; margin-top: 20px;">请及时检查机器人状态并进行处理。</p>
                        <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
                        <p style="color: #999; font-size: 12px; margin-bottom: 0;">此邮件由 NapCat 管理系统自动发送，请勿回复。</p>
                    </div>
                </div>
            `
        };

        // Send email
        await transporter.sendMail(mailOptions);
        writeLog('SYSTEM', '邮件通知', `已发送掉线通知邮件: ${botName || botId} (${reason})`);
        console.log(`✅ Offline email sent for bot ${botId} (${reason})`);

    } catch (error) {
        console.error('Failed to send offline email:', error.message);
        writeLog('SYSTEM', '邮件发送失败', `发送失败: ${error.message}`);
    }
};

// --- Middleware ---
app.set('trust proxy', TRUST_PROXY);
const isPrivateIp = (ip) => {
    if (!ip) return false;
    if (ip === 'localhost') return true;
    const parts = ip.split('.').map(n => parseInt(n, 10));
    if (parts.length !== 4 || parts.some(n => Number.isNaN(n))) return false;
    if (parts[0] === 10) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    return ip === '127.0.0.1';
};

app.use((req, res, next) => {
    const origin = req.headers.origin;
    const host = req.headers.host;
    const dynamicOrigins = host ? [`http://${host}`, `https://${host}`] : [];
    const allowList = new Set([...ALLOWED_ORIGINS, ...DEFAULT_ALLOWED_ORIGINS, ...dynamicOrigins]);
    if (origin) {
        try {
            const originUrl = new URL(origin);
            const originHost = originUrl.hostname;
            if (!allowList.has(origin) && !isPrivateIp(originHost)) {
                return res.status(403).json({ error: 'Not allowed by CORS' });
            }
        } catch (e) {
            return res.status(403).json({ error: 'Not allowed by CORS' });
        }
    }
    return cors({ origin: true })(req, res, next);
});
app.use(express.json({ limit: '1mb' }));

// --- Routes ---
app.get('/lincyppq', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/index.css', (req, res) => res.sendFile(path.join(__dirname, 'index.css')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.get('/', (req, res) => res.status(403).send('Access Denied.'));

// --- DB Loading ---
let botsDB = {};
if (fs.existsSync(DB_FILE)) {
    try { botsDB = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) { }
}
botsDB = normalizeBotsDB(botsDB);
const saveDB = () => queueWrite(DB_FILE, botsDB);

const activeConnections = new Map();
const botErrorCount = new Map(); // Track consecutive errors per bot
const healthCheckPending = new Map(); // Track pending health checks
const pendingRequests = new Map();
const isBotOnline = (bot) => {
    const ws = activeConnections.get(String(bot.id));
    if (!ws || ws.readyState !== WebSocket.OPEN) return false;
    const lastSeen = typeof bot.lastSeen === 'number' ? bot.lastSeen : 0;
    return Date.now() - lastSeen <= WS_OFFLINE_AFTER_MS;
};
const markBotSeen = (botId) => {
    if (!botsDB[botId]) return;
    const wasOnline = botsDB[botId].status === 'online';
    botsDB[botId].lastSeen = Date.now();
    if (!wasOnline) {
        botsDB[botId].status = 'online';
        writeLog('BOT', '机器人上线', `账号 ${botId} 心跳确认`);
        saveDB();
    }
};

// --- WebSocket ---
wss.on('connection', (ws, req) => {
    const wsToken = req.headers['x-ws-token'];
    if (WS_TOKEN && wsToken !== WS_TOKEN) {
        ws.close(1008, 'Unauthorized');
        return;
    }
    const selfId = req.headers['x-self-id'] || req.headers['x-client-role'];

    if (selfId) {
        console.log(`NapCat Connected: ${selfId}`);
        activeConnections.set(String(selfId), ws);
        ws.isAlive = true;
        ws.on('pong', () => {
            ws.isAlive = true;
            markBotSeen(String(selfId));
        });

        if (!botsDB[selfId]) {
            botsDB[selfId] = normalizeBot({ id: selfId, name: `Bot ${selfId}`, status: 'offline', contracts: [] });
            saveDB();
        } else {
            if (botsDB[selfId].deleted) {
                botsDB[selfId].deleted = false;
                delete botsDB[selfId].deletedAt;
            }
            botsDB[selfId] = normalizeBot(botsDB[selfId]);
            saveDB();
        }

        ws.on('close', () => {
            activeConnections.delete(String(selfId));
            if (botsDB[selfId]) {
                botsDB[selfId].status = 'offline';
                // Send email notification immediately on disconnect
                const botName = botsDB[selfId].name || `Bot ${selfId}`;
                sendOfflineEmail(String(selfId), botName).catch(err => {
                    console.error('Email notification error:', err);
                });
            }
            writeLog('BOT', '机器人下线', `账号 ${selfId} 已断开`);
        });

        ws.on('message', (message) => {
            try {
                ws.isAlive = true;
                markBotSeen(String(selfId));
                const msg = JSON.parse(message);

                // --- 方案一：检测消息发送失败 ---
                if (msg.status === 'failed' || (msg.retcode && msg.retcode < 0)) {
                    const currentCount = (botErrorCount.get(String(selfId)) || 0) + 1;
                    botErrorCount.set(String(selfId), currentCount);

                    console.warn(`⚠️ Bot ${selfId} error detected (${currentCount}/3):`, msg.data?.errMsg || msg.message || 'Unknown error');

                    if (currentCount >= 3) {
                        const botName = botsDB[selfId]?.name || `Bot ${selfId}`;
                        sendOfflineEmail(String(selfId), botName, '连续发送失败').catch(err => {
                            console.error('Email notification error:', err);
                        });
                        writeLog('BOT', '功能异常', `账号 ${selfId} 连续发送失败`);
                        botErrorCount.set(String(selfId), 0); // 重置计数
                    }
                } else if (msg.status === 'ok' || (msg.retcode !== undefined && msg.retcode === 0)) {
                    // 成功响应，重置错误计数
                    botErrorCount.set(String(selfId), 0);
                }

                // --- 方案四：健康检查响应 ---
                if (msg.echo && msg.echo.startsWith('health_check_')) {
                    healthCheckPending.delete(msg.echo);
                    // 健康检查成功，重置错误计数
                    botErrorCount.set(String(selfId), 0);
                    return;
                }

                if (msg.echo && pendingRequests.has(msg.echo)) {
                    const { resolve } = pendingRequests.get(msg.echo);
                    resolve(msg);
                    pendingRequests.delete(msg.echo);
                    return;
                }

                if (msg.post_type === 'message' && (msg.message_type === 'group' || (msg.message && msg.message_type === 'group'))) {
                    const rawText = msg.raw_message || msg.message || "";
                    const groupId = msg.group_id;
                    const prefix = adminConfig.cmdPrefix || 'xa';
                    const queryCmd = prefix + (adminConfig.cmdQuery || '查询到期');
                    const renewCmd = prefix + (adminConfig.cmdRenew || '续费');

                    if (rawText.startsWith(queryCmd)) {
                        const botData = botsDB[selfId];
                        if (botData.deleted) return;
                        const contract = botData?.contracts?.find(c => String(c.groupId) === String(groupId) && !c.deleted);
                        let replyText = "";
                        if (!contract) replyText = "本群暂无授权记录或不在管理列表中。";
                        else if (!contract.expireTime) replyText = "本群授权为永久有效。";
                        else {
                            const diff = contract.expireTime - Date.now();
                            if (diff <= 0) replyText = "本群授权已过期，请及时续费。";
                            else {
                                const days = Math.floor(diff / (1000 * 60 * 60 * 24));
                                const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
                                replyText = `剩余时间：${days}天 ${hours}小时`;
                            }
                        }
                        ws.send(JSON.stringify({ action: 'send_group_msg', params: { group_id: groupId, message: replyText } }));
                        writeLog('BOT', '自动回复(查询)', `回复群 ${groupId}: ${replyText}`);
                    }

                    if (rawText.startsWith(renewCmd)) {
                        ws.send(JSON.stringify({ action: 'send_group_msg', params: { group_id: groupId, message: adminConfig.renewalMessage } }));
                        writeLog('BOT', '自动回复(续费)', `回复群 ${groupId}: 续费指引`);
                    }

                    // --- 鸣潮功能指令触发到期提醒 ---
                    if (isWutheringWavesCommand(rawText, prefix, queryCmd, renewCmd)) {
                        const botData = botsDB[selfId];
                        if (!botData || botData.deleted) return;

                        const contract = botData.contracts?.find(c => String(c.groupId) === String(groupId) && !c.deleted);
                        if (!contract) return; // 无授权记录，不处理

                        // 检查是否已到期
                        if (!contract.expireTime) return; // 永久授权，不处理
                        const now = Date.now();
                        if (contract.expireTime > now) return; // 未到期，不处理

                        // 检查冷却时间（从后台配置读取，单位：分钟）
                        const cooldownMinutes = adminConfig.commandExpireNoticeCooldown || 30;
                        const cooldownMs = cooldownMinutes * 60 * 1000;
                        if (contract.lastCommandExpireNoticeAt && (now - contract.lastCommandExpireNoticeAt < cooldownMs)) {
                            return; // 冷却中，不重复发送
                        }

                        // 发送到期通知（只发送到期通知内容，不拼接续费指引，与原有自动到期通知逻辑保持一致）
                        const notifyMsg = adminConfig.defaultNotifyMessage || '[系统通知] 本群机器人服务已到期，请联系管理员续费。';

                        ws.send(JSON.stringify({ action: 'send_group_msg', params: { group_id: groupId, message: notifyMsg } }));
                        writeLog('BOT', '指令触发到期提醒', `群 ${groupId} 触发鸣潮指令，发送到期通知`);

                        // 更新冷却时间
                        contract.lastCommandExpireNoticeAt = now;
                        queueWrite(DB_FILE, botsDB);
                    }
                }

                // --- 自动处理加群邀请（智能同步授权 + 防薅羊毛）---
                if (msg.post_type === 'request' && msg.request_type === 'group' && msg.sub_type === 'invite') {
                    if (!adminConfig.autoHandleGroupInvite) return; // 未开启自动处理

                    const botData = botsDB[selfId];
                    if (!botData || botData.deleted) return;

                    const groupId = String(msg.group_id);
                    const flag = msg.flag;
                    const inviterUid = msg.user_id;

                    let approve = false;
                    let reason = '';
                    let foundContract = null;

                    // 1. 先检查当前机器人是否有该群的授权
                    let contract = botData.contracts?.find(c => String(c.groupId) === groupId && !c.deleted);

                    // 2. 如果当前机器人没有授权，检查其他机器人是否有该群的授权（跨机器人同步）
                    if (!contract) {
                        for (const otherId in botsDB) {
                            if (otherId === String(selfId)) continue; // 跳过自己
                            const otherBot = botsDB[otherId];
                            if (otherBot.deleted) continue;

                            const otherContract = otherBot.contracts?.find(c => String(c.groupId) === groupId && !c.deleted);
                            if (otherContract) {
                                foundContract = otherContract;
                                break;
                            }
                        }

                        // 如果找到其他机器人的授权，同步到当前机器人
                        if (foundContract) {
                            contract = {
                                id: genId(),
                                groupId: foundContract.groupId,
                                groupName: foundContract.groupName,
                                expireTime: foundContract.expireTime,
                                deleted: false,
                                leftGroup: false,
                                notified: false,
                                preNotified: false,
                                lastDaysAdded: null,
                                daysAddedAt: null,
                                lastCommandExpireNoticeAt: null
                            };
                            botData.contracts.push(contract);
                            writeLog('BOT', '自动同步授权', `从其他机器人同步群 ${groupId} 的授权到机器人 ${selfId}`);
                        }
                    }

                    // 3. 防薅羊毛：检查该群是否已有其他机器人在群里
                    let hasOtherBotInGroup = false;
                    for (const otherId in botsDB) {
                        if (otherId === String(selfId)) continue; // 跳过自己
                        const otherBot = botsDB[otherId];
                        if (otherBot.deleted) continue;

                        const otherContract = otherBot.contracts?.find(c => String(c.groupId) === groupId && !c.deleted);
                        // 如果其他机器人有该群的授权，且没有标记为已退群，说明可能在群里
                        if (otherContract && !otherContract.leftGroup) {
                            hasOtherBotInGroup = true;
                            break;
                        }
                    }

                    // 4. 判断是否同意邀请
                    if (!contract) {
                        // 无授权记录（任何机器人都没有），拒绝
                        approve = false;
                        reason = '该群未在任何机器人的授权列表中';
                    } else if (hasOtherBotInGroup) {
                        // 已有其他机器人在群里，拒绝（防薅羊毛）
                        approve = false;
                        reason = '该群已有其他机器人，禁止重复加群';
                    } else if (!contract.expireTime) {
                        // 永久授权，同意
                        approve = true;
                        reason = '永久授权';
                    } else {
                        // 检查是否到期
                        const now = Date.now();
                        if (contract.expireTime > now) {
                            approve = true;
                            const days = Math.floor((contract.expireTime - now) / (1000 * 60 * 60 * 24));
                            reason = `授权有效，剩余${days}天`;
                        } else {
                            approve = false;
                            reason = '授权已过期';
                        }
                    }

                    // 5. 发送处理请求
                    ws.send(JSON.stringify({
                        action: 'set_group_add_request',
                        params: {
                            flag: flag,
                            sub_type: 'invite',
                            approve: approve
                        }
                    }));

                    // 6. 如果同意了，保存数据（标记该群已被当前机器人占用）
                    if (approve) {
                        queueWrite(DB_FILE, botsDB);
                    }

                    writeLog('BOT', approve ? '同意加群邀请' : '拒绝加群邀请',
                        `机器人: ${selfId}, 群: ${groupId}, 邀请人: ${inviterUid}, 原因: ${reason}`);
                }

                // --- 监听退群通知（自动标记 leftGroup）---
                if (msg.post_type === 'notice' && msg.notice_type === 'group_decrease' && msg.sub_type === 'leave') {
                    const botData = botsDB[selfId];
                    if (!botData || botData.deleted) return;

                    const groupId = String(msg.group_id);
                    const userId = String(msg.user_id);

                    // 如果是机器人自己退群
                    if (userId === String(selfId)) {
                        const contract = botData.contracts?.find(c => String(c.groupId) === groupId && !c.deleted);
                        if (contract) {
                            contract.leftGroup = true;
                            queueWrite(DB_FILE, botsDB);
                            writeLog('BOT', '检测到退群', `机器人 ${selfId} 已退出群 ${groupId}，标记 leftGroup=true`);
                        }
                    }
                }

                // --- 监听被踢出群通知 ---
                if (msg.post_type === 'notice' && msg.notice_type === 'group_decrease' && msg.sub_type === 'kick_me') {
                    const botData = botsDB[selfId];
                    if (!botData || botData.deleted) return;

                    const groupId = String(msg.group_id);

                    const contract = botData.contracts?.find(c => String(c.groupId) === groupId && !c.deleted);
                    if (contract) {
                        contract.leftGroup = true;
                        queueWrite(DB_FILE, botsDB);
                        writeLog('BOT', '检测到被踢出群', `机器人 ${selfId} 被踢出群 ${groupId}，标记 leftGroup=true`);
                    }
                }

                // --- 监听进群通知（重置 leftGroup）---
                if (msg.post_type === 'notice' && msg.notice_type === 'group_increase' && msg.sub_type === 'approve') {
                    const botData = botsDB[selfId];
                    if (!botData || botData.deleted) return;

                    const groupId = String(msg.group_id);
                    const userId = String(msg.user_id);

                    // 如果是机器人自己进群
                    if (userId === String(selfId)) {
                        const contract = botData.contracts?.find(c => String(c.groupId) === groupId && !c.deleted);
                        if (contract) {
                            contract.leftGroup = false;
                            queueWrite(DB_FILE, botsDB);
                            writeLog('BOT', '检测到进群', `机器人 ${selfId} 已进入群 ${groupId}，标记 leftGroup=false`);
                        }
                    }
                }
            } catch (e) { }
        });
    }
});

setInterval(() => {
    wss.clients.forEach((ws) => {
        if (ws.isAlive === false) {
            ws.terminate();
            return;
        }
        ws.isAlive = false;
        try { ws.ping(); } catch (e) { }
    });
    const now = Date.now();
    Object.keys(botsDB).forEach(id => {
        if (!botsDB[id]) return;
        const ws = activeConnections.get(String(id));
        const lastSeen = botsDB[id].lastSeen || 0;
        const shouldBeOnline = ws && ws.readyState === WebSocket.OPEN && (now - lastSeen <= WS_OFFLINE_AFTER_MS);
        if (!shouldBeOnline && botsDB[id].status !== 'offline') {
            botsDB[id].status = 'offline';
            writeLog('BOT', '机器人离线', `账号 ${id} 心跳超时`);
            // Send email notification on heartbeat timeout
            const botName = botsDB[id].name || `Bot ${id}`;
            sendOfflineEmail(String(id), botName).catch(err => {
                console.error('Email notification error:', err);
            });
        }
    });
}, WS_HEARTBEAT_INTERVAL_MS);

// --- 方案四：定期健康检查 (每2分钟) ---
setInterval(() => {
    Object.keys(botsDB).forEach(botId => {
        if (botsDB[botId].deleted || botsDB[botId].status === 'offline') return;

        const ws = activeConnections.get(String(botId));
        if (!ws || ws.readyState !== WebSocket.OPEN) return;

        const echo = `health_check_${botId}_${Date.now()}`;
        healthCheckPending.set(echo, botId);

        // 发送健康检查请求
        try {
            ws.send(JSON.stringify({
                action: 'get_login_info',
                echo: echo
            }));

            // 5秒后检查是否收到响应
            setTimeout(() => {
                if (healthCheckPending.has(echo)) {
                    healthCheckPending.delete(echo);
                    const botName = botsDB[botId]?.name || `Bot ${botId}`;
                    console.warn(`⚠️ Bot ${botId} health check failed (no response)`);
                    sendOfflineEmail(String(botId), botName, '健康检查失败').catch(err => {
                        console.error('Email notification error:', err);
                    });
                    writeLog('BOT', '健康检查失败', `账号 ${botId} 无响应`);
                }
            }, 5000);
        } catch (err) {
            console.error(`Health check send error for bot ${botId}:`, err.message);
        }
    });
}, 2 * 60 * 1000); // 每2分钟检查一次

const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.sendStatus(401);
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        if (isDefaultPassword()) {
            const allowPaths = new Set(['/api/admin/change-password', '/api/admin/config']);
            if (!allowPaths.has(req.path)) {
                return res.status(403).json({ error: 'Password change required', mustChangePassword: true });
            }
        }
        next();
    });
};

const isDefaultPassword = () => {
    if (!adminConfig.passwordHash) return false;
    return bcrypt.compareSync('admin123', adminConfig.passwordHash);
};

const ensureJwtSecret = (cb) => {
    if (JWT_SECRET) {
        if (!fs.existsSync(JWT_SECRET_FILE)) {
            try { fs.writeFileSync(JWT_SECRET_FILE, JWT_SECRET); } catch (e) { }
        }
        return cb();
    }
    if (fs.existsSync(JWT_SECRET_FILE)) {
        try {
            const saved = fs.readFileSync(JWT_SECRET_FILE, 'utf8').trim();
            if (saved) {
                JWT_SECRET = saved;
                return cb();
            }
        } catch (e) { }
    }
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const ask = () => {
        rl.question('输入秘钥: ', (answer) => {
            const trimmed = String(answer || '').trim();
            if (!trimmed) {
                console.log('JWT_SECRET is required.');
                return ask();
            }
            JWT_SECRET = trimmed;
            try { fs.writeFileSync(JWT_SECRET_FILE, JWT_SECRET); } catch (e) { }
            rl.close();
            cb();
        });
    };
    ask();
};

const sanitizeAdminUpdate = (input = {}) => {
    const allowedKeys = new Set([
        'defaultNotifyMessage',
        'warningDays',
        'warningMessage',
        'renewalMessage',
        'backupRetentionDays',
        'autoQuit',
        'quitWaitHours',
        'quitMessage',
        'cmdPrefix',
        'cmdQuery',
        'cmdRenew',
        'commandExpireNoticeCooldown',
        'autoHandleGroupInvite',
        'uiTheme',
        'emailNotification'
    ]);
    const out = {};
    Object.keys(input).forEach(key => {
        if (!allowedKeys.has(key)) return;
        if (key === 'uiTheme' && input.uiTheme && typeof input.uiTheme === 'object') {
            out.uiTheme = {
                primaryColor: String(input.uiTheme.primaryColor || adminConfig.uiTheme?.primaryColor || '#007AFF'),
                backgroundImage: String(input.uiTheme.backgroundImage || ''),
                overlayOpacity: typeof input.uiTheme.overlayOpacity === 'number' ? input.uiTheme.overlayOpacity : adminConfig.uiTheme?.overlayOpacity ?? 0.4
            };
            return;
        }
        if (key === 'emailNotification' && input.emailNotification && typeof input.emailNotification === 'object') {
            out.emailNotification = {
                enabled: Boolean(input.emailNotification.enabled),
                smtpHost: String(input.emailNotification.smtpHost || adminConfig.emailNotification?.smtpHost || 'smtp.qq.com'),
                smtpPort: parseInt(input.emailNotification.smtpPort, 10) || 465,
                smtpSecure: Boolean(input.emailNotification.smtpSecure ?? true),
                smtpUser: String(input.emailNotification.smtpUser || ''),
                smtpPass: String(input.emailNotification.smtpPass || ''),
                recipientEmail: String(input.emailNotification.recipientEmail || '')
            };
            return;
        }
        out[key] = input[key];
    });
    if (typeof out.warningDays !== 'undefined') out.warningDays = parseInt(out.warningDays, 10) || 0;
    if (typeof out.backupRetentionDays !== 'undefined') out.backupRetentionDays = parseInt(out.backupRetentionDays, 10) || 0;
    if (typeof out.quitWaitHours !== 'undefined') out.quitWaitHours = parseInt(out.quitWaitHours, 10) || 0;
    return out;
};

// --- API ---
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const ip = req.ip || '';
    const cleanIp = String(ip).replace(/^::ffff:/, '');

    if (!checkRateLimit(cleanIp)) return res.status(429).json({ error: '尝试次数过多，IP 已暂时锁定 15 分钟' });

    const hasHash = Boolean(adminConfig.passwordHash);
    const passwordMatch = hasHash
        ? bcrypt.compareSync(password || '', adminConfig.passwordHash)
        : (password === adminConfig.password);

    if (username === adminConfig.username && passwordMatch) {
        recordLoginAttempt(cleanIp, true);
        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '24h' });
        writeLog('ACCESS', '登录成功', `用户 ${username} 登录成功`);
        recordLogin(username, ip, true);
        res.json({ token, mustChangePassword: isDefaultPassword() });
    } else {
        recordLoginAttempt(cleanIp, false);
        writeLog('ACCESS', '登录失败', `IP: ${cleanIp} 尝试登录 ${username} 失败`);
        recordLogin(username || 'unknown', ip, false);
        res.status(401).json({ error: 'Auth failed' });
    }
});

app.get('/api/admin/login-history', authenticateToken, (req, res) => res.json(loginHistory));

app.post('/api/admin/change-password', authenticateToken, (req, res) => {
    const { newUsername, newPassword } = req.body;
    const finalUsername = newUsername ? String(newUsername) : adminConfig.username;
    if (newUsername) adminConfig.username = String(newUsername);
    if (newPassword) adminConfig.passwordHash = bcrypt.hashSync(String(newPassword), 10);
    saveAdminConfig();
    writeLog('ACCESS', '修改密码', '管理员账号/密码已修改');
    const newToken = jwt.sign({ username: finalUsername }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ success: true, token: newToken });
});

app.get('/api/admin/config', authenticateToken, (req, res) => {
    res.json({
        mustChangePassword: isDefaultPassword(),
        username: adminConfig.username,
        defaultNotifyMessage: adminConfig.defaultNotifyMessage,
        warningDays: adminConfig.warningDays,
        warningMessage: adminConfig.warningMessage,
        renewalMessage: adminConfig.renewalMessage,
        backupRetentionDays: adminConfig.backupRetentionDays,
        autoQuit: adminConfig.autoQuit,
        quitWaitHours: adminConfig.quitWaitHours,
        quitMessage: adminConfig.quitMessage,
        cmdPrefix: adminConfig.cmdPrefix,
        cmdQuery: adminConfig.cmdQuery,
        cmdRenew: adminConfig.cmdRenew,
        commandExpireNoticeCooldown: adminConfig.commandExpireNoticeCooldown,
        autoHandleGroupInvite: adminConfig.autoHandleGroupInvite,
        uiTheme: adminConfig.uiTheme,
        emailNotification: adminConfig.emailNotification
    });
});

app.post('/api/admin/config', authenticateToken, (req, res) => {
    Object.assign(adminConfig, sanitizeAdminUpdate(req.body));
    saveAdminConfig();
    writeLog('OPERATION', '更新配置', '全局系统配置已更新');
    res.json({ success: true });
});

app.post('/api/admin/test-msg', authenticateToken, (req, res) => {
    const { targetGroup, msgType } = req.body;
    let message = '';
    if (msgType === 'renewal') message = adminConfig.renewalMessage;
    else if (msgType === 'expire') message = adminConfig.defaultNotifyMessage;
    else if (msgType === 'warning') message = adminConfig.warningMessage;
    else if (msgType === 'quit') message = adminConfig.quitMessage;
    else return res.status(400).json({ error: 'Unknown message type' });

    const onlineBotId = Object.keys(botsDB).find(id => activeConnections.has(id) && !botsDB[id].deleted);
    if (!onlineBotId) return res.status(503).json({ error: '没有在线的机器人实例' });

    const ws = activeConnections.get(onlineBotId);
    ws.send(JSON.stringify({ action: 'send_group_msg', params: { group_id: parseInt(targetGroup), message } }));
    res.json({ success: true });
});

app.post('/api/admin/test-email', authenticateToken, async (req, res) => {
    try {
        const emailConfig = adminConfig.emailNotification;

        if (!emailConfig.smtpUser || !emailConfig.smtpPass || !emailConfig.recipientEmail) {
            return res.status(400).json({ error: '邮箱配置不完整，请先配置 SMTP 信息' });
        }

        const transporter = nodemailer.createTransport({
            host: emailConfig.smtpHost,
            port: emailConfig.smtpPort,
            secure: emailConfig.smtpSecure,
            auth: {
                user: emailConfig.smtpUser,
                pass: emailConfig.smtpPass
            }
        });

        const now = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });

        const mailOptions = {
            from: `"NapCat 监控系统" <${emailConfig.smtpUser}>`,
            to: emailConfig.recipientEmail,
            subject: '📧 测试邮件 - NapCat 监控系统',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f5f5f5;">
                    <div style="background-color: #fff; border-radius: 8px; padding: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                        <h2 style="color: #4CAF50; margin-top: 0;">✅ 测试邮件发送成功！</h2>
                        <p>恭喜！您的邮件通知配置正确。</p>
                        <div style="background-color: #e8f5e9; border-left: 4px solid #4CAF50; padding: 15px; margin: 20px 0;">
                            <p style="margin: 5px 0;"><strong>发送时间：</strong>${now}</p>
                            <p style="margin: 5px 0;"><strong>SMTP 服务器：</strong>${emailConfig.smtpHost}:${emailConfig.smtpPort}</p>
                        </div>
                        <p style="color: #666; margin-top: 20px;">当机器人掉线时，系统会自动发送通知邮件到此邮箱。</p>
                        <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
                        <p style="color: #999; font-size: 12px; margin-bottom: 0;">此邮件由 NapCat 管理系统发送。</p>
                    </div>
                </div>
            `
        };

        await transporter.sendMail(mailOptions);
        writeLog('SYSTEM', '测试邮件', '测试邮件发送成功');
        res.json({ success: true, message: '测试邮件已发送，请检查收件箱' });

    } catch (error) {
        console.error('Test email failed:', error.message);
        writeLog('SYSTEM', '测试邮件失败', `错误: ${error.message}`);
        res.status(500).json({ error: `发送失败: ${error.message}` });
    }
});

app.get('/api/logs', authenticateToken, (req, res) => res.json(logs));
app.post('/api/backup/now', authenticateToken, (req, res) => { performBackup(); res.json({ success: true }); });
app.get('/api/backups', authenticateToken, (req, res) => {
    try {
        const files = fs.readdirSync(BACKUPS_DIR).map(file => {
            const stats = fs.statSync(path.join(BACKUPS_DIR, file));
            return { name: file, size: (stats.size / 1024).toFixed(2) + ' KB', created: stats.mtime };
        }).sort((a, b) => b.created - a.created);
        res.json(files);
    } catch (e) { res.json([]); }
});
app.get('/api/backup/:filename', authenticateToken, (req, res) => {
    const safeName = path.basename(req.params.filename);
    if (safeName !== req.params.filename) return res.status(400).send('Invalid filename');
    const resolved = path.resolve(BACKUPS_DIR, safeName);
    const root = path.resolve(BACKUPS_DIR);
    if (!resolved.startsWith(root + path.sep)) return res.status(400).send('Invalid path');
    if (fs.existsSync(resolved)) res.download(resolved);
    else res.status(404).send('Not found');
});

app.post('/api/backup/restore', authenticateToken, uploadBackup.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    try {
        const filePath = req.file.path;
        const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        let restoredType = 'Unknown';
        if (data.username && data.uiTheme) {
            if (data.username) adminConfig.username = String(data.username);
            if (data.passwordHash) adminConfig.passwordHash = data.passwordHash;
            Object.assign(adminConfig, sanitizeAdminUpdate(data));
            saveAdminConfig();
            restoredType = '系统配置';
        } else if (typeof data === 'object') {
            botsDB = normalizeBotsDB(data);
            saveDB();
            restoredType = '机器人数据';
        }
        fs.unlinkSync(filePath);
        writeLog('OPERATION', '备份恢复', `恢复: ${restoredType}`);
        res.json({ success: true, type: restoredType });
    } catch (e) { res.status(400).json({ error: 'Invalid file' }); }
});

app.get('/api/bots', authenticateToken, (req, res) => {
    const list = Object.values(botsDB).filter(bot => !bot.deleted).map(bot => {
        const normalized = normalizeBot(bot);
        return {
            ...normalized,
            contracts: (normalized.contracts || []).filter(c => !c.deleted),
            isOnline: isBotOnline(normalized)
        };
    });
    res.json(list);
});

app.post('/api/bot/create', authenticateToken, (req, res) => {
    const { id, name, avatar } = req.body;
    const botId = id !== undefined ? String(id) : '';
    if (!botId) return res.status(400).json({ error: 'Invalid ID' });
    if (botsDB[botId]) {
        if (botsDB[botId].deleted) {
            botsDB[botId].deleted = false;
            botsDB[botId].name = name || botsDB[botId].name;
            botsDB[botId].avatar = normalizeBotAvatar(botId, botsDB[botId].avatar);
            saveDB();
            return res.json({ success: true });
        }
        return res.status(400).json({ error: 'Exists' });
    }
    botsDB[botId] = normalizeBot({ id: botId, name: name || `Bot ${botId}`, status: 'offline', contracts: [], avatar });
    saveDB();
    writeLog('OPERATION', '添加实例', `添加实例: ${botId}`);
    res.json({ success: true });
});

app.post('/api/bot/update-info', authenticateToken, (req, res) => {
    const { id, name, avatar } = req.body;
    const botId = id !== undefined ? String(id) : '';
    if (botsDB[botId]) {
        botsDB[botId].name = name;
        if (avatar !== undefined) botsDB[botId].avatar = normalizeBotAvatar(botId, avatar);
        saveDB();
        res.json({ success: true });
    } else res.status(404).json({ error: 'Not Found' });
});

app.post('/api/bot/group-info', authenticateToken, async (req, res) => {
    const { botId, groupId } = req.body;
    const ws = activeConnections.get(String(botId));
    if (!ws || ws.readyState !== WebSocket.OPEN) return res.status(500).json({ error: 'Bot Offline' });
    const echo = Date.now().toString(36) + Math.random().toString(36).substr(2);
    const responsePromise = new Promise((resolve, reject) => {
        const timeout = setTimeout(() => { pendingRequests.delete(echo); reject(new Error('Timeout')); }, 5000);
        pendingRequests.set(echo, { resolve: (data) => { clearTimeout(timeout); resolve(data); }, reject });
    });
    ws.send(JSON.stringify({ action: 'get_group_info', params: { group_id: parseInt(groupId), no_cache: true }, echo }));
    try {
        const data = await responsePromise;
        res.json(data.data ? { groupName: data.data.group_name } : { error: 'Failed' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/bot/ghost-scan', authenticateToken, async (req, res) => {
    const { botId } = req.body;
    const ws = activeConnections.get(String(botId));
    if (!ws || ws.readyState !== WebSocket.OPEN) return res.status(500).json({ error: 'Bot Offline' });
    const echo = Date.now().toString(36) + Math.random().toString(36).substr(2);
    const responsePromise = new Promise((resolve, reject) => {
        const timeout = setTimeout(() => { pendingRequests.delete(echo); reject(new Error('Timeout')); }, 5000);
        pendingRequests.set(echo, { resolve: (data) => { clearTimeout(timeout); resolve(data); }, reject });
    });
    ws.send(JSON.stringify({ action: 'get_group_list', echo }));
    try {
        const data = await responsePromise;
        if (data.status === 'ok' && Array.isArray(data.data)) {
            const authorizedGroupIds = new Set((botsDB[botId]?.contracts || []).filter(c => !c.deleted && !c.leftGroup).map(c => String(c.groupId)));
            const ghosts = data.data.filter(g => !authorizedGroupIds.has(String(g.group_id))).map(g => ({
                group_id: g.group_id, group_name: g.group_name, member_count: g.member_count
            }));
            res.json(ghosts);
        } else res.status(400).json({ error: 'Failed' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/bot/ghost-clean', authenticateToken, (req, res) => {
    const { botId, groupIds } = req.body;
    const ws = activeConnections.get(String(botId));
    if (ws && ws.readyState === WebSocket.OPEN) {
        let count = 0;
        groupIds.forEach(gid => {
            ws.send(JSON.stringify({ action: 'set_group_leave', params: { group_id: parseInt(gid) } }));
            count++;
        });
        writeLog('OPERATION', '清理幽灵群', `清理了 ${count} 个群`);
        res.json({ success: true, count });
    } else res.status(500).json({ error: 'Bot Offline' });
});

app.post('/api/bot/group-list', authenticateToken, async (req, res) => {
    const { botId } = req.body;
    const ws = activeConnections.get(String(botId));
    if (!ws || ws.readyState !== WebSocket.OPEN) return res.status(500).json({ error: 'Bot Offline' });
    const echo = Date.now().toString(36) + Math.random().toString(36).substr(2);
    const responsePromise = new Promise((resolve, reject) => {
        const timeout = setTimeout(() => { pendingRequests.delete(echo); reject(new Error('Timeout')); }, 5000);
        pendingRequests.set(echo, { resolve: (data) => { clearTimeout(timeout); resolve(data); }, reject });
    });
    ws.send(JSON.stringify({ action: 'get_group_list', echo }));
    try {
        const data = await responsePromise;
        res.json(data.data || []);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/bot/contract/save', authenticateToken, (req, res) => {
    const { botId, contractId, groupId, groupName, expireTime } = req.body;
    if (!botsDB[botId]) return res.status(404).json({ error: 'Not Found' });
    let contract = botsDB[botId].contracts.find(c => c.id === contractId);
    if (contract) {
        const oldExpireTime = contract.expireTime || 0;
        const newExpireTime = typeof expireTime === 'number' ? expireTime : null;

        // Track days added if expireTime increased
        if (newExpireTime && oldExpireTime && newExpireTime > oldExpireTime) {
            const daysAdded = Math.round((newExpireTime - oldExpireTime) / (1000 * 60 * 60 * 24));
            contract.lastDaysAdded = daysAdded;
            contract.daysAddedAt = Date.now();
        }

        if (newExpireTime > oldExpireTime) {
            contract.notified = false;
            contract.preNotified = false;
            contract.leftGroup = false;
        }
        contract.groupId = String(groupId);
        contract.expireTime = newExpireTime;
        if (groupName) contract.groupName = groupName;
        writeLog('OPERATION', '更新授权', `群: ${groupId}`);
    } else {
        botsDB[botId].contracts.push({
            id: genId(),
            groupId: String(groupId),
            groupName: groupName || `群 ${groupId}`,
            expireTime: typeof expireTime === 'number' ? expireTime : null,
            notified: false,
            preNotified: false,
            leftGroup: false,
            lastDaysAdded: null,
            daysAddedAt: null
        });
        writeLog('OPERATION', '新增授权', `群: ${groupId}`);
    }
    saveDB();
    res.json({ success: true });
});

app.post('/api/bot/contract/delete', authenticateToken, (req, res) => {
    const { botId, contractId } = req.body;
    if (botsDB[botId]) {
        const contract = botsDB[botId].contracts.find(c => c.id === contractId);
        if (contract) {
            contract.deleted = true; contract.deletedAt = Date.now();
            saveDB();
            writeLog('OPERATION', '删除授权', `授权ID: ${contractId}`);
            res.json({ success: true });
        } else res.status(404).json({ error: 'Contract Not Found' });
    } else res.status(404).json({ error: 'Bot Not Found' });
});

app.post('/api/bot/contract/transfer', authenticateToken, (req, res) => {
    const { fromBotId, toBotId, contractId } = req.body;
    if (!fromBotId || !toBotId || !contractId) return res.status(400).json({ error: 'Missing fields' });
    if (String(fromBotId) === String(toBotId)) return res.status(400).json({ error: 'Same bot' });
    const fromBot = botsDB[fromBotId];
    const toBot = botsDB[toBotId];
    if (!fromBot || fromBot.deleted) return res.status(404).json({ error: 'Source bot not found' });
    if (!toBot || toBot.deleted) return res.status(404).json({ error: 'Target bot not found' });
    const idx = (fromBot.contracts || []).findIndex(c => c.id === contractId && !c.deleted);
    if (idx === -1) return res.status(404).json({ error: 'Contract not found' });

    const contract = fromBot.contracts[idx];
    fromBot.contracts.splice(idx, 1);
    if (!toBot.contracts) toBot.contracts = [];

    const newContract = normalizeContract({
        ...contract,
        leftGroup: false,
        preNotified: false,
        notified: false
    });
    delete newContract.deleted;
    delete newContract.deletedAt;
    if (toBot.contracts.some(c => c.id === newContract.id)) {
        newContract.id = genId();
    }
    toBot.contracts.push(newContract);
    saveDB();
    writeLog('OPERATION', '转移授权', `群 ${contract.groupId} 从 ${fromBotId} 转移到 ${toBotId}`);
    res.json({ success: true, id: newContract.id });
});

app.post('/api/bot/quit-group', authenticateToken, (req, res) => {
    const { botId, groupId } = req.body;
    const ws = activeConnections.get(String(botId));
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ action: 'set_group_leave', params: { group_id: parseInt(groupId) } }));
        const contract = botsDB[botId]?.contracts.find(c => String(c.groupId) === String(groupId));
        if (contract) { contract.leftGroup = true; saveDB(); }
        writeLog('OPERATION', '手动退群', `群: ${groupId}`);
        res.json({ success: true });
    } else res.status(500).json({ error: 'Bot Offline' });
});

app.post('/api/bot/delete', authenticateToken, (req, res) => {
    const { id } = req.body;
    if (botsDB[id]) {
        botsDB[id].deleted = true; botsDB[id].deletedAt = Date.now();
        saveDB();
        writeLog('OPERATION', '删除实例', `实例: ${id}`);
        res.json({ success: true });
    } else res.status(404).json({ error: 'Not Found' });
});

app.post('/api/bot/send', authenticateToken, (req, res) => {
    const { id, group_id, message } = req.body;
    const ws = activeConnections.get(String(id));
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ action: 'send_group_msg', params: { group_id: parseInt(group_id), message } }));
        writeLog('OPERATION', '发送消息', `群: ${group_id}`);
        res.json({ success: true });
    } else res.status(500).json({ error: 'Bot Offline' });
});

app.post('/api/bot/pause-rental', authenticateToken, (req, res) => {
    const { botId } = req.body;
    if (!botsDB[botId]) return res.status(404).json({ error: 'Bot not found' });
    const bot = botsDB[botId];
    if (bot.pausedAt) return res.json({ success: true, alreadyPaused: true });
    bot.pausedAt = Date.now();
    saveDB();
    writeLog('OPERATION', '暂停扣时', `机器人 ${botId} 已暂停租赁扣时`);
    res.json({ success: true });
});

app.post('/api/bot/resume-rental', authenticateToken, (req, res) => {
    const { botId } = req.body;
    const bot = botsDB[botId];
    if (!bot) return res.status(404).json({ error: 'Bot not found' });

    if (!bot.pausedAt) return res.json({ success: true, alreadyResumed: true });

    const pausedMs = Date.now() - bot.pausedAt;
    if (bot.contracts && pausedMs > 0) {
        bot.contracts.forEach(c => {
            if (!c || c.deleted || !c.expireTime) return;
            c.expireTime += pausedMs;
        });
    }

    bot.pausedAt = null;
    saveDB();
    writeLog('OPERATION', '恢复扣时', `机器人 ${botId} 已恢复租赁扣时，补回 ${Math.round(pausedMs / (1000 * 60 * 60))} 小时`);
    res.json({ success: true, restoredMs: pausedMs });
});

app.post('/api/bot/bulk-extend-days', authenticateToken, (req, res) => {
    const { botId, days } = req.body;
    const daysNum = parseInt(days, 10);

    if (!daysNum || daysNum <= 0) {
        return res.status(400).json({ error: '天数必须是正整数' });
    }

    if (!botsDB[botId]) {
        return res.status(404).json({ error: 'Bot not found' });
    }

    const now = Date.now();
    const msToAdd = daysNum * 24 * 60 * 60 * 1000;

    let extendedCount = 0;
    let skippedPermanent = 0;
    let skippedExpired = 0;
    let skippedDeleted = 0;

    const bot = botsDB[botId];
    bot.contracts.forEach(contract => {
        if (contract.deleted) {
            skippedDeleted++;
            return;
        }

        if (!contract.expireTime) {
            skippedPermanent++;
            return;
        }

        if (contract.expireTime <= now) {
            skippedExpired++;
            return;
        }

        contract.expireTime += msToAdd;
        contract.lastDaysAdded = daysNum;
        contract.daysAddedAt = now;
        extendedCount++;
    });

    if (extendedCount > 0) {
        saveDB();
    }

    writeLog('OPERATION', '批量加天数', `机器人 ${botId} 增加 ${daysNum} 天,影响 ${extendedCount} 个合约`);

    res.json({
        success: true,
        extended: extendedCount,
        skipped: {
            permanent: skippedPermanent,
            expired: skippedExpired,
            deleted: skippedDeleted
        },
        days: daysNum
    });
});

app.post('/api/admin/bulk-extend-days', authenticateToken, (req, res) => {
    const { days } = req.body;
    const daysNum = parseInt(days, 10);

    if (!daysNum || daysNum <= 0) {
        return res.status(400).json({ error: '天数必须是正整数' });
    }

    const now = Date.now();
    const msToAdd = daysNum * 24 * 60 * 60 * 1000;

    let extendedCount = 0;
    let skippedPermanent = 0;
    let skippedExpired = 0;
    let skippedDeleted = 0;

    Object.values(botsDB).forEach(bot => {
        if (bot.deleted) return;

        bot.contracts.forEach(contract => {
            if (contract.deleted) {
                skippedDeleted++;
                return;
            }

            if (!contract.expireTime) {
                skippedPermanent++;
                return;
            }

            if (contract.expireTime <= now) {
                skippedExpired++;
                return;
            }

            contract.expireTime += msToAdd;
            contract.lastDaysAdded = daysNum;
            contract.daysAddedAt = now;
            extendedCount++;
        });
    });

    if (extendedCount > 0) {
        saveDB();
    }

    writeLog('OPERATION', '批量加天数', `增加 ${daysNum} 天,影响 ${extendedCount} 个合约`);

    res.json({
        success: true,
        extended: extendedCount,
        skipped: {
            permanent: skippedPermanent,
            expired: skippedExpired,
            deleted: skippedDeleted
        },
        days: daysNum
    });
});


app.post('/api/upload', authenticateToken, uploadImage.single('image'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file' });
    res.json({ url: `/uploads/${req.file.filename}` });
});

app.get('/api/recycle-bin', authenticateToken, (req, res) => {
    const deletedBots = Object.values(botsDB).filter(b => b.deleted);
    let deletedContracts = [];
    Object.values(botsDB).forEach(bot => {
        if (bot.contracts) bot.contracts.forEach(c => { if (c.deleted) deletedContracts.push({ ...c, botId: bot.id, botName: bot.name }); });
    });
    res.json({ bots: deletedBots, contracts: deletedContracts });
});

app.post('/api/recycle-bin/restore', authenticateToken, (req, res) => {
    const { type, id, botId } = req.body;
    if (type === 'bot' && botsDB[id]) {
        botsDB[id].deleted = false; delete botsDB[id].deletedAt;
        saveDB(); res.json({ success: true });
    } else if (type === 'contract' && botsDB[botId]) {
        const c = botsDB[botId].contracts.find(c => c.id === id);
        if (c) { c.deleted = false; delete c.deletedAt; saveDB(); res.json({ success: true }); }
        else res.status(404).json({ error: 'Not found' });
    } else res.status(400).json({ error: 'Invalid' });
});

app.post('/api/recycle-bin/purge', authenticateToken, (req, res) => {
    const { type, id, botId } = req.body;
    if (type === 'bot' && botsDB[id]) { delete botsDB[id]; saveDB(); res.json({ success: true }); }
    else if (type === 'contract' && botsDB[botId]) {
        botsDB[botId].contracts = botsDB[botId].contracts.filter(c => c.id !== id);
        saveDB(); res.json({ success: true });
    } else res.status(400).json({ error: 'Invalid' });
});

app.use((err, req, res, next) => {
    if (!err) return next();
    if (err instanceof multer.MulterError || (err.message && err.message.startsWith('Invalid'))) {
        return res.status(400).json({ error: err.message });
    }
    res.status(500).json({ error: 'Server error' });
});

cron.schedule('* * * * *', () => {
    const now = Date.now();
    let changed = false;
    const notifyMsg = adminConfig.defaultNotifyMessage;
    const warnMsg = adminConfig.warningMessage;
    const warnTime = (adminConfig.warningDays || 3) * 24 * 60 * 60 * 1000;
    const quitWaitTime = (adminConfig.quitWaitHours || 24) * 60 * 60 * 1000;

    Object.values(botsDB).forEach(bot => {
        if (bot.deleted || bot.pausedAt) return;
        const ws = activeConnections.get(String(bot.id));
        const isOnline = ws && ws.readyState === WebSocket.OPEN;
        bot.contracts.forEach(c => {
            if (c.deleted || !c.expireTime) return;
            if (!c.preNotified && !c.notified && (c.expireTime - now < warnTime) && (c.expireTime > now)) {
                if (isOnline) {
                    ws.send(JSON.stringify({ action: 'send_group_msg', params: { group_id: parseInt(c.groupId), message: warnMsg } }));
                    writeLog('BOT', '发送预警', `群: ${c.groupId}`);
                    c.preNotified = true; changed = true;
                }
            }
            if (!c.notified && now > c.expireTime) {
                if (isOnline) {
                    ws.send(JSON.stringify({ action: 'send_group_msg', params: { group_id: parseInt(c.groupId), message: notifyMsg } }));
                    writeLog('BOT', '发送到期', `群: ${c.groupId}`);
                    c.notified = true; changed = true;
                }
            }
            if (adminConfig.autoQuit && !c.leftGroup && now > (c.expireTime + quitWaitTime)) {
                if (isOnline) {
                    ws.send(JSON.stringify({ action: 'send_group_msg', params: { group_id: parseInt(c.groupId), message: adminConfig.quitMessage } }));
                    setTimeout(() => {
                        if (activeConnections.get(String(bot.id))) ws.send(JSON.stringify({ action: 'set_group_leave', params: { group_id: parseInt(c.groupId) } }));
                    }, 2000);
                    writeLog('BOT', '自动退群', `群: ${c.groupId}`);
                    c.leftGroup = true; changed = true;
                }
            }
        });
    });
    if (changed) saveDB();
});

cron.schedule('0 3 * * *', () => {
    performBackup();
    const now = Date.now();
    const sevenDays = 7 * 24 * 60 * 60 * 1000;
    let dbChanged = false;
    Object.keys(botsDB).forEach(id => {
        if (botsDB[id].deleted && (now - botsDB[id].deletedAt > sevenDays)) { delete botsDB[id]; dbChanged = true; }
        else if (botsDB[id].contracts) {
            const originalLen = botsDB[id].contracts.length;
            botsDB[id].contracts = botsDB[id].contracts.filter(c => !c.deleted || (now - c.deletedAt <= sevenDays));
            if (botsDB[id].contracts.length !== originalLen) dbChanged = true;
        }
    });
    if (dbChanged) saveDB();
});

ensureJwtSecret(() => {
    server.listen(PORT, '0.0.0.0', () => {
        console.log(`NapCat Admin Panel: http://localhost:${PORT}/lincyppq`);
    });
});
