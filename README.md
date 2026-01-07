# WafCat

📦 **雷池WAF攻击流量导出与分析工具**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.0+-green.svg)](https://flask.palletsprojects.com/)

## 简介

WafCat 是一款专门为雷池WAF设计的攻击流量导出工具，适用于无会员情况下的应急导出和分析。该工具包含两个核心功能模块：
- **WafCat.py**：导出攻击流量数据
- **app.py**：对导出的流量进行统计分析和可视化呈现

## 快速开始

### 1. 攻击流量导出 (WafCat.py)

#### 功能
快速导出雷池WAF中的攻击流量数据，支持自定义导出范围和条件。

#### 使用步骤

1. **配置参数**
   - 打开 `WafCat.py` 文件
   - 修改 `IP` 字段为您的雷池Waf服务器IP地址
   - 修改 `Authorization` 字段为您的认证凭证
   - 修改 `TOTAL_PAGES` 字段为您的日志页数
   
2. **运行导出**
   ```bash
   python WafCat.py
   ```
   - 程序将自动导出攻击流量数据
   - 导出的文件将保存在 `logs` 目录下

### 2. 流量统计分析 (app.py)

#### 功能
对导出的攻击流量文件进行统计分析，提供可视化图表展示。

#### 使用步骤

1. **准备数据**
   - 确保已通过 `WafCat.py` 导出攻击流量文件
   - 导出文件需保存在 `logs` 目录下

2. **启动分析服务**
   ```bash
   python app.py
   ```
   - 程序将启动一个Web服务
   - 在浏览器中访问提示的URL（默认为 `http://localhost:5000`）即可查看统计结果

## 功能特性

### 导出工具特性
- 支持批量导出攻击流量数据
- 自动分页处理大量数据
- 导出为JSON格式，便于后续分析
- 可自定义导出范围和条件

### 分析工具特性
- **可视化统计**：提供攻击类型分布、风险等级分布、攻击源IP排行等图表
- **实时搜索**：支持按IP、URL、攻击类型等关键字搜索
- **详细分析**：查看单个攻击事件的完整HTTP请求和响应

## 注意事项

⚠️ **安全提示**
- 请确保您有权限访问雷池Waf服务器
- 导出的攻击流量数据可能包含敏感信息，请妥善保管
- 建议定期更新认证凭证以确保安全性
- 运行环境需要Python 3.8及以上版本
- 仅用于个人紧急情况下的研究用途，还请支持长亭科技的付费服务。

## 运行环境

### 依赖库
- requests
- flask

### 安装依赖
```bash
pip install requests flask
```

## 项目结构

```
WafCat/
├── WafCat.py          # 攻击流量导出工具
├── app.py             # 流量统计分析工具
├── templates/         # HTML模板文件
│   └── index.html     # 主页面模板
└── logs/              # 导出的攻击流量数据目录
```
