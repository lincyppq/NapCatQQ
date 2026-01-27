##  环境准备

安装 Node.js 22.x（如已安装可跳过）：

``` bash
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs
```

验证安装：

``` bash
node -v   # 应输出 v22.x.x
npm -v    # 应输出 10.x.x
```

##  安装依赖

在项目根目录执行：

``` bash
npm install
```

##  启动项目

使用以下命令启动服务：

``` bash
node server.js
```

##  访问 Web 面板

在浏览器打开：

    http://localhost:23333

如需外网访问，请进行内网穿透或开放 54321 公网端口。

登录信息：

-   默认账号：`admin`
-   默认密码：`admin123`

##  WebSocket 连接地址
可在server.js更改端口
    ws://127.0.0.1:23333/ws/napcat

##  命令（可自定义）
    
-   `xa查询到期`
-   `xa续费`
