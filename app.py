import os
import json
import math
import time
from functools import lru_cache
from flask import Flask, render_template, request, jsonify
from collections import Counter

app = Flask(__name__)

# 配置日志所在的文件夹路径
LOG_DIR = os.path.join(os.path.dirname(__file__), 'logs')

class LogCache:
    """简易的内存缓存，用于存储日志摘要信息以便快速搜索和统计"""
    def __init__(self):
        self.data = []
        self.last_load_time = 0
        self.is_loaded = False

    def load_data(self):
        """扫描目录读取所有日志供检索"""
        if not os.path.exists(LOG_DIR):
            os.makedirs(LOG_DIR)
        
        temp_list = []
        files = [f for f in os.listdir(LOG_DIR) if f.endswith('.json')]
        
        print(f"[*]正在索引 {len(files)} 个日志文件...")
        
        for fname in files:
            fpath = os.path.join(LOG_DIR, fname)
            try:
                # 仅读取我们需要搜索和列表展示的字段
                with open(fpath, 'r', encoding='utf-8') as f:
                    content = json.load(f)
                    log_data = content.get('data', {})
                    
                    summary = {
                        'filename': fname,
                        'id': log_data.get('EventId', ''),
                        'time': log_data.get('timestamp', 0),
                        'src_ip': log_data.get('src_ip', '-'),
                        'host': log_data.get('host', '-'),
                        'url': log_data.get('url_path', '-'),
                        'attack_type': log_data.get('reason', 'Unknown'),
                        'risk_level': log_data.get('risk_level', 1),
                        'country': log_data.get('country', '-'),
                        'province': log_data.get('province', '') # 用于搜索
                    }
                    temp_list.append(summary)
            except Exception as e:
                continue
        
        # 按时间倒序排序
        temp_list.sort(key=lambda x: x['time'], reverse=True)
        self.data = temp_list
        self.is_loaded = True
        print(f"[*] 索引完成，共加载 {len(self.data)} 条记录")

# 初始化缓存实例
cache = LogCache()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/refresh')
def api_refresh():
    """强制刷新缓存"""
    cache.load_data()
    return jsonify({'msg': 'ok', 'count': len(cache.data)})

@app.route('/api/stats')
def api_stats():
    """返回统计数据用于图表展示"""
    if not cache.is_loaded:
        cache.load_data()
        
    logs = cache.data
    
    # 1. 风险等级统计
    risk_counts = Counter([x['risk_level'] for x in logs])
    
    # 2. 攻击类型分布
    attack_types = Counter([x['attack_type'] for x in logs])
    
    # 3. Top 10 攻击源IP
    top_ips = Counter([x['src_ip'] for x in logs]).most_common(10)
    
    return jsonify({
        'total_count': len(logs),
        'risk_stats': {
            'high': risk_counts.get(3, 0),
            'medium': risk_counts.get(2, 0),
            'low': risk_counts.get(1, 0)
        },
        'attack_type_stats': dict(attack_types),
        'top_ips': [{'ip': ip, 'count': count} for ip, count in top_ips]
    })

@app.route('/api/logs')
def api_logs():
    """获取日志列表（支持分页和搜索）"""
    if not cache.is_loaded:
        cache.load_data()
        
    query = request.args.get('q', '').strip().lower()
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('limit', 15))
    
    # 搜索过滤逻辑
    if query:
        filtered_files = [
            x for x in cache.data 
            if query in x['src_ip'] 
            or query in x['url'].lower() 
            or query in x['attack_type'].lower()
            or query in x['host'].lower()
            or query in x['id'].lower()
        ]
    else:
        filtered_files = cache.data
        
    total_files = len(filtered_files)
    total_pages = math.ceil(total_files / per_page) if total_files > 0 else 1
    
    # 切片分页
    start = (page - 1) * per_page
    end = start + per_page
    target_data = filtered_files[start:end]
    
    return jsonify({
        'total': total_files,
        'page': page,
        'pages': total_pages,
        'logs': target_data
    })

@app.route('/api/log_detail')
def api_log_detail():
    """获取详情保持不变，依旧实时读取文件"""
    filename = request.args.get('filename')
    fpath = os.path.join(LOG_DIR, filename)
    if not os.path.exists(fpath):
        return jsonify({'error': 'File not found'}), 404
    try:
        with open(fpath, 'r', encoding='utf-8') as f:
            return jsonify(json.load(f))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # 启动时预热缓存
    print("[*] 正在预热日志缓存...")
    cache.load_data()
    app.run(debug=True, host='0.0.0.0', port=5000)