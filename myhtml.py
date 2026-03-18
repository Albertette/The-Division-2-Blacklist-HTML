import hashlib
import re
import os
import sys
import time
import functools
import logging
import json
import socket
import tarfile
import io
import ipaddress
import shutil
import threading
from threading import Timer
from werkzeug.security import generate_password_hash, check_password_hash
from waitress import serve
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, session, redirect, flash, jsonify, make_response
from flask_limiter import Limiter
from flask_mysqldb import MySQL
from datetime import datetime

# ================================
# 【混合引擎】ip2region (国内) + GeoIP2 (国外City+ASN)
# ================================
import ip2region.util as util
import ip2region.searcher as xdb
import geoip2.database
import geoip2.errors
import requests

# ---------------------
# 修复路径 & 自动创建目录
# ---------------------
if not os.path.exists("geoip"):
    os.makedirs("geoip")

IP2REGION_V4_PATH = "ip2region_v4.xdb"
IP2REGION_V6_PATH = "ip2region_v6.xdb"
GEO_CITY_PATH = "geoip/GeoLite2-City.mmdb"
GEO_ASN_PATH = "geoip/GeoLite2-ASN.mmdb"

# 全局搜索器
v4_searcher = None
v6_searcher = None
city_reader = None
asn_reader = None

# ==========================
# IP 缓存系统（你要加的）
# ==========================
BLACKLIST_FILE = "ip_blacklist.json"
ATTACK_STATS_FILE = "attack_stats.json"
IP_CACHE_PATH = "ip_location_cache.json"
ip_location_cache = {}
file_monitor = {"blacklist": 0, "stats": 0}

# =============================
# 配置读取
# =============================
def load_config():
    config_path = os.path.join("config", "config.json")
    if not os.path.exists(config_path):
        raise Exception("配置文件不存在: config/config.json")
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)

config = load_config()
GEO_CONFIG = config.get("geoip", {})
MAXMIND_ACCOUNT_ID = GEO_CONFIG.get("account_id", "")
MAXMIND_LICENSE_KEY = GEO_CONFIG.get("license_key", "")
ROOT_SUPER_ADMINS = config.get("root_super_admin")

# =============================
# 全球机房 ASN（高可信）
# =============================
DATACENTER_ASN = {
    8075,  # Microsoft
    16509,  # Amazon
    14618,  # Amazon
    15169,  # Google
    14061,  # DigitalOcean
    16276,  # OVH
    24940,  # Hetzner
    20473,  # Vultr
    63949,  # Linode
    13335,  # Cloudflare
    54113,  # Fastly
    20940,  # Akamai
    45102,  # Alibaba
    132203,  # Tencent
    55990,  # Huawei
    31898,  # Oracle
    36351,  # IBM
}

# =============================
# 【修复】可用的下载地址
# =============================
UPDATE_URLS = {
    "ip2region_v4.xdb": "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region.xdb",
    "ip2region_v6.xdb": "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ipv6.xdb",
    "GeoLite2-City.mmdb": "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb",
    "GeoLite2-ASN.mmdb": "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb",
}

AUTO_UPDATE_DB = False
UPDATE_INTERVAL = 86400

# ====================
# 配置
# ====================
CLOUDFLARE_IP_SET = []
LAST_REFRESH_TIME = 0
REFRESH_INTERVAL = 3600  # 1小时刷新一次（秒）

# ====================
# 刷新 CF IP 列表
# ====================
def refresh_cloudflare_ips():
    global CLOUDFLARE_IP_SET, LAST_REFRESH_TIME
    try:
        ips_v4 = requests.get("https://www.cloudflare.com/ips-v4", timeout=5).text.split()
        ips_v6 = requests.get("https://www.cloudflare.com/ips-v6", timeout=5).text.split()
        CLOUDFLARE_IP_SET = [ipaddress.ip_network(cidr, strict=False) for cidr in ips_v4 + ips_v6]
        LAST_REFRESH_TIME = time.time()
        print("✅ Cloudflare IP 段已自动刷新")
    except Exception as e:
        print("❌ CF IP 刷新失败", e)

# 第一次启动时加载
refresh_cloudflare_ips()

# ====================
# 判断是否 CF IP
# ====================
def is_cloudflare_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in net for net in CLOUDFLARE_IP_SET)
    except:
        return False

def download_file(url, save_path):
    try:
        resp = requests.get(url, stream=True, timeout=15)
        resp.raise_for_status()
        with open(save_path, "wb") as f:
            f.write(resp.content)
        return True
    except Exception as e:
        print(f"❌ 下载失败: {e}")
        return False

def backup_old_db(file_path):
    if os.path.exists(file_path):
        bak_path = file_path + ".bak"
        shutil.copyfile(file_path, bak_path)

def update_ip_databases():
    if not AUTO_UPDATE_DB:
        return
    print("\n【自动更新】检查 IP 库版本...")
    updated = False

    # ip2region v4
    try:
        backup_old_db(IP2REGION_V4_PATH)
        if download_file(UPDATE_URLS["ip2region_v4.xdb"], IP2REGION_V4_PATH):
            print("✅ ip2region_v4 更新成功")
            updated = True
    except:
        pass

    # ip2region v6
    try:
        backup_old_db(IP2REGION_V6_PATH)
        if download_file(UPDATE_URLS["ip2region_v6.xdb"], IP2REGION_V6_PATH):
            print("✅ ip2region_v6 更新成功")
            updated = True
    except:
        pass

    # GeoLite2-City
    try:
        backup_old_db(GEO_CITY_PATH)
        if download_file(UPDATE_URLS["GeoLite2-City.mmdb"], GEO_CITY_PATH):
            print("✅ GeoLite2-City 更新成功")
            updated = True
    except:
        pass

    # GeoLite2-ASN
    try:
        backup_old_db(GEO_ASN_PATH)
        if download_file(UPDATE_URLS["GeoLite2-ASN.mmdb"], GEO_ASN_PATH):
            print("✅ GeoLite2-ASN 更新成功")
            updated = True
    except:
        pass

    if updated:
        try:
            init_ip_engine()
            print("🔄 数据库已热重载")
        except:
            pass
    print("【自动更新】完成\n")

def auto_update_task():
    update_ip_databases()
    t = Timer(UPDATE_INTERVAL, auto_update_task)
    t.daemon = True
    t.start()

def init_ip_engine():
    global v4_searcher, v6_searcher, city_reader, asn_reader
    try:
        util.verify_from_file(IP2REGION_V4_PATH)
        util.verify_from_file(IP2REGION_V6_PATH)
        v4_idx = util.load_vector_index_from_file(IP2REGION_V4_PATH)
        v6_idx = util.load_vector_index_from_file(IP2REGION_V6_PATH)
        v4_searcher = xdb.new_with_vector_index(util.IPv4, IP2REGION_V4_PATH, v4_idx)
        v6_searcher = xdb.new_with_vector_index(util.IPv6, IP2REGION_V6_PATH, v6_idx)
        print("✅ ip2region 初始化完成")
    except Exception as e:
        print(f"❌ ip2region 失败: {e}")

    try:
        city_reader = geoip2.database.Reader(GEO_CITY_PATH)
        asn_reader = geoip2.database.Reader(GEO_ASN_PATH)
        print("✅ GeoIP2 初始化完成")
    except Exception as e:
        print(f"⚠️ GeoIP2 初始化失败（首次运行会自动下载）: {e}")

# ==========================
# IP 缓存系统（原子写入 + 开机全量强制同步 + 自动增删）
# ==========================

# 加载缓存
def load_ip_cache():
    global ip_location_cache
    if os.path.exists(IP_CACHE_PATH):
        with open(IP_CACHE_PATH, "r", encoding="utf-8") as f:
            ip_location_cache = json.load(f)

# 🔥 原子写入保存缓存（安全不损坏）
def save_ip_cache():
    tmp_path = IP_CACHE_PATH + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(ip_location_cache, f, ensure_ascii=False, indent=2)
    os.replace(tmp_path, IP_CACHE_PATH)

# 获取两个文件所有 IP
def get_all_ips():
    black_ips = set()
    stats_ips = set()
    if os.path.exists(BLACKLIST_FILE):
        try:
            with open(BLACKLIST_FILE, "r", encoding="utf-8") as f:
                black_ips = set(json.load(f).keys())
        except:
            pass
    if os.path.exists(ATTACK_STATS_FILE):
        try:
            with open(ATTACK_STATS_FILE, "r", encoding="utf-8") as f:
                stats_ips = set(json.load(f).keys())
        except:
            pass
    return list(black_ips | stats_ips)

# 批量查询缺失IP
def batch_query_ips(ips):
    updated = False
    for ip in ips:
        if ip not in ip_location_cache:
            country, prov, city, isp, is_dc = get_ip_detail(ip)
            typ = get_ip_display_type(isp)
            ip_location_cache[ip] = {
                "status": "ok",
                "country": country,
                "province": prov,
                "city": city,
                "isp": isp,
                "type": typ
            }
            updated = True
    if updated:
        save_ip_cache()

# ==========================
# 🔥 核心：全量强制同步（重启必跑）
# 功能：
# 1. 缓存多了 → 删除
# 2. 缓存少了 → 查询补上
# 3. 最终完全一致
# ==========================
def full_sync_ip_cache():
    print("\n[IP 缓存] 开机全量同步检查中...")

    # 真实存在的 IP（黑名单 + 攻击统计）
    real_ips = set(get_all_ips())
    # 缓存里的 IP
    cache_ips = set(ip_location_cache.keys())

    # 1. 缓存多出来的：删除
    to_remove = [ip for ip in cache_ips if ip not in real_ips]
    for ip in to_remove:
        del ip_location_cache[ip]

    # 2. 缓存缺少的：批量查询补上
    to_add = [ip for ip in real_ips if ip not in cache_ips]
    batch_query_ips(to_add)

    # 3. 最终原子保存一次
    if to_remove or to_add:
        save_ip_cache()
        print(f"[IP 缓存] 同步完成 | 移除 {len(to_remove)} 个 | 新增 {len(to_add)} 个")
    else:
        print("[IP 缓存] 缓存已完全一致\n")

# 增量同步（运行时用）
def sync_ip_cache():
    full_sync_ip_cache()

# 后台监听文件变化
def file_watcher():
    while True:
        try:
            b_mtime = os.path.getmtime(BLACKLIST_FILE) if os.path.exists(BLACKLIST_FILE) else 0
            s_mtime = os.path.getmtime(ATTACK_STATS_FILE) if os.path.exists(ATTACK_STATS_FILE) else 0
            if b_mtime != file_monitor["blacklist"] or s_mtime != file_monitor["stats"]:
                sync_ip_cache()
                file_monitor["blacklist"] = b_mtime
                file_monitor["stats"] = s_mtime
        except:
            pass
        time.sleep(2)

# 初始化（重启必做全量同步）
def init_ip_cache_system():
    load_ip_cache()
    full_sync_ip_cache()  # 🔥 重启强制检查
    t = threading.Thread(target=file_watcher, daemon=True)
    t.start()

def is_ipv6(ip: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except:
        return False

def ip_query_local(ip: str):
    try:
        if is_ipv6(ip) and v6_searcher:
            return v6_searcher.search(ip)
        elif not is_ipv6(ip) and v4_searcher:
            return v4_searcher.search(ip)
    except:
        pass
    return ""

def ip_query_geo(ip: str):
    if not city_reader or not asn_reader:
        return "Unknown", "", "", "Unknown", False

    try:

        g = city_reader.city(ip)
        a = asn_reader.asn(ip)

        country = g.country.names.get("zh-CN") or g.country.name or "Unknown"
        prov = g.subdivisions.most_specific.names.get("zh-CN") or g.subdivisions.most_specific.name or ""
        city = g.city.names.get("zh-CN") or g.city.name or ""

        isp = a.autonomous_system_organization or "Unknown"
        asn = a.autonomous_system_number or 0

        isp_map = {
            "Tencent": "腾讯",
            "Alibaba": "阿里",
            "Aliyun": "阿里",
            "Huawei": "华为",
            "Baidu": "百度",
            "JD": "京东",
            "Kingsoft": "金山",
        }


        # --------------------------
        # ASN优先判断
        # --------------------------
        if asn in DATACENTER_ASN:
            is_dc = True
        else:
            is_dc = is_datacenter(isp)

        # 只对港澳台生效
        if country in ["中国", "香港", "澳门", "台湾"]:
            for en, cn in isp_map.items():
                if en in isp:
                    isp = cn
                    break

        return country, prov, city, isp, is_dc

    except:
        return "Unknown", "", "", "Unknown", False

def parse_region(region: str):
    c, p, ci, isp, _ = (region.split("|") + ["未知"] * 5)[:5]
    # 处理香港：去掉0
    if c == "中国" and p == "香港特别行政区" and ci == "0":
        ci = ""
    # 处理澳门：强制修正
    if c == "中国" and p == "澳门":
        p = "澳门特别行政区"
    return (
        c if c != "0" else "未知",
        p if p != "0" else "",
        ci if ci != "0" else "",
        isp if isp != "0" else "未知"
    )

def format_isp_name(isp: str, country: str = "中国"):
    if not isp or isp in ("0", "未知", "Unknown"):
        return isp

    isp_upper = isp.upper()

    # 国内：极简
    if country in ["中国", "香港", "澳门", "台湾"]:
        if "MOBILE" in isp_upper or "移动" in isp:
            return "移动"
        elif "CHINANET" in isp_upper or "电信" in isp:
            return "电信"
        elif "UNICOM" in isp_upper or "联通" in isp:
            return "联通"
        elif "BROADCAST" in isp_upper or "BROADNET" in isp_upper or "广电" in isp:
            return "广电"
    # 国外：全称
    else:
        if "CHINANET" in isp_upper:
            return "中国电信"
        elif "CHINA MOBILE" in isp_upper:
            return "中国移动"
        elif "CHINA UNICOM" in isp_upper:
            return "中国联通"
        elif "BROADCAST" in isp_upper or "BROADNET" in isp_upper:
            return "中国广电"

    return isp

# =============================
# 【前端显示专用】获取IP精细类型
# 完全使用你原来的 is_datacenter 关键词
# =============================
def get_ip_display_type(isp: str):
    isp = isp.upper()

    # 手机
    mobile_keywords = ["LTE", "5G", "4G", "MOBILE", "WIRELESS", "CELLULAR", "CMCC", "UNICOM", "CTGNET"]
    for kw in mobile_keywords:
        if kw in isp:
            return "手机"

    # 住宅（你原来的家庭宽带列表）
    home_keywords = [
        "电信", "联通", "移动", "广电", "铁通",
        "CHINA TELECOM", "CHINA MOBILE", "CHINA UNICOM",
        "COMCAST", "VERIZON", "AT&T", "SPECTRUM",
        "家庭", "宽带", "HOME", "BROADBAND"
    ]
    for kw in home_keywords:
        if kw in isp:
            return "住宅"

    # CDN
    cdn_keywords = ["CLOUDFLARE", "AKAMAI", "FASTLY"]
    for kw in cdn_keywords:
        if kw in isp:
            return "CDN"

    # 云服务器（你原来全部国内+国外云）
    cloud_keywords = [
        "MICROSOFT", "AZURE", "AMAZON", "AWS", "GOOGLE", "GCLOUD",
        "阿里云", "腾讯云", "华为云", "百度云", "金山云", "京东云",
        "阿里", "腾讯", "华为", "百度", "金山", "京东",
        "UCloud", "优刻得", "青云", "浪潮", "帝联", "蓝汛"
    ]
    for kw in cloud_keywords:
        if kw in isp:
            return "云服务器"

    # VPS（你原来完整列表）
    vps_keywords = [
        "DIGITALOCEAN", "OVH", "VULTR", "LINODE", "CONTABO", "HETZNER",
        "SCALWAY", "IONOS", "LEASEWEB", "GCORE", "TIMEWEB", "REG.RU"
    ]
    for kw in vps_keywords:
        if kw in isp:
            return "VPS"

    # 机房
    dc_keywords = ["DATACENTER", "HOSTING", "SERVER", "VPS", "CLOUD", "CDN"]
    for kw in dc_keywords:
        if kw in isp:
            return "机房"

    return "未知"

def is_datacenter(isp: str):
    isp = isp.upper()

    # --------------------------
    # 家庭宽带排除
    # --------------------------
    home_isps = [
        "电信", "联通", "移动", "广电", "铁通",
        "CHINA TELECOM", "CHINA MOBILE", "CHINA UNICOM",
        "COMCAST", "VERIZON", "AT&T", "SPECTRUM",
        "家庭", "宽带", "HOME", "BROADBAND",
        "LTE", "5G", "4G"
    ]

    for kw in home_isps:
        if kw in isp:
            return False

    # --------------------------
    # 云 / VPS / CDN
    # --------------------------
    cloud_keywords = [

        # 云厂商
        "MICROSOFT", "AZURE",
        "AMAZON", "AWS",
        "GOOGLE", "GCLOUD",
        "DIGITALOCEAN",
        "OVH",
        "VULTR",
        "LINODE",
        "CONTABO",
        "HETZNER",

        # 国内云
        "阿里云",
        "腾讯云",
        "华为云",
        "百度云",
        "金山云",
        "京东云",
        "阿里",
        "腾讯",
        "华为",
        "百度",
        "金山",
        "京东",
        "UCloud",
        "优刻得",
        "青云",
        "浪潮",
        "帝联",
        "蓝汛",

        # CDN
        "CLOUDFLARE",
        "AKAMAI",
        "FASTLY",

        # VPS
        "SCALWAY",
        "IONOS",
        "LEASEWEB",
        "GCORE",
        "TIMEWEB",
        "REG.RU",

        # 机房
        "DATACENTER",
        "HOSTING",
        "SERVER",
        "VPS",
        "CLOUD",
        "CDN"
    ]

    for kw in cloud_keywords:
        if kw in isp:
            return True

    return False

@functools.lru_cache(maxsize=20000)
def get_ip_location(ip: str):
    if ip in ("127.0.0.1", "::1"):
        loc = "本机"
        risk = "安全"
        return f"{loc} ({risk})"

    # 优先查询 GeoLite2
    geo_country, geo_prov, geo_city, geo_isp, geo_is_dc = ip_query_geo(ip)

    # 判断是否需要 ip2region 兜底
    use_ip2region = False
    if not is_ipv6(ip):
        # IPv4 保持原有逻辑
        region = ip_query_local(ip)
        if region:
            country, prov, city, isp = parse_region(region)
            if country == "中国":
                if prov in ["香港特别行政区", "澳门特别行政区", "台湾省"] and isp in ("未知", "0", ""):
                    if geo_isp and geo_isp != "Unknown":
                        isp = geo_isp
                is_dc = is_datacenter(isp)
                loc = f"{prov} {city}".strip() if not is_dc else prov
                tag = "[机房]" if is_dc else ""
                risk = "高危" if is_dc else "低危"
                return f"{loc}{tag} ({risk})"
    else:
        # ===================== IPv6 新逻辑 =====================
        # Geo 查到有效位置 + 有效运营商 → 直接用
        geo_location_valid = (geo_country not in ("Unknown", ""))
        geo_isp_valid = (geo_isp not in ("Unknown", ""))

        if geo_location_valid and geo_isp_valid:
            # 两项都完整 → 直接用 Geo
            country, prov, city, isp, is_dc = geo_country, geo_prov, geo_city, geo_isp, geo_is_dc
        else:
            # 任意缺失 → ip2region 兜底
            region = ip_query_local(ip)
            if region:
                country, prov, city, isp = parse_region(region)
                is_dc = is_datacenter(isp)
            else:
                # 都查不到 → 保持 Geo 结果
                country, prov, city, isp, is_dc = geo_country, geo_prov, geo_city, geo_isp, geo_is_dc

        # 拼接显示
        if country == "中国":
            loc = f"{prov} {city}".strip() if not is_dc else prov
        else:
            loc = f"{country} {prov} {city}".strip()

        tag = "[机房]" if is_dc else ""
        risk = "高危" if is_dc else "低危"
        return f"{loc}{tag} ({risk})"

    # 兜底：全部用 Geo
    loc = f"{geo_country} {geo_prov} {geo_city}".strip()
    tag = "[机房]" if geo_is_dc else ""
    risk = "高危" if geo_is_dc else "低危"
    return f"{loc}{tag} ({risk})"

def get_ip_detail(ip: str):
    # ===================== 核心：IPv6 优先 Geo + 缺失项 ip2region 兜底 =====================
    if is_ipv6(ip):
        # 1. 先查 GeoLite2
        geo_country, geo_prov, geo_city, geo_isp, geo_is_dc = ip_query_geo(ip)

        # 2. 判断有效性
        geo_has_location = (geo_country not in (None, "", "Unknown"))
        geo_has_isp = (geo_isp not in (None, "", "Unknown"))

        # 3. 两项都完整 → 直接返回
        if geo_has_location and geo_has_isp:
            geo_isp = format_isp_name(geo_isp, geo_country)
            return geo_country, geo_prov, geo_city, geo_isp, geo_is_dc

        # 4. 任意缺失 → 用 ip2region 兜底查询
        region = ip_query_local(ip)
        if region:
            c, p, ci, isp = parse_region(region)
            is_dc = is_datacenter(isp)
            isp = format_isp_name(isp, c)
            return c, p, ci, isp, is_dc

        # 5. 都查不到 → 返回 Geo 原始结果
        geo_isp = format_isp_name(geo_isp, geo_country)
        return geo_country, geo_prov, geo_city, geo_isp, geo_is_dc

    # ===================== IPv4 保持原有逻辑不变 =====================
    region = ip_query_local(ip)
    if region:
        c, p, ci, isp = parse_region(region)
        if c == "中国":
            if p in ["香港特别行政区", "澳门特别行政区", "台湾省"] and isp in ("未知", "0", ""):
                _, _, _, geo_isp, geo_dc = ip_query_geo(ip)
                if geo_isp and geo_isp != "Unknown":
                    isp = geo_isp
            isp = format_isp_name(isp, c)
            return c, p, ci, isp, is_datacenter(isp)
    c, p, ci, isp, dc = ip_query_geo(ip)
    isp = format_isp_name(isp, c)
    return c, p, ci, isp, dc

# ================================
# 初始化
# ================================
init_ip_engine()
auto_update_task()

# =============================
# PyInstaller支持
# =============================
def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

# =============================
# 真实IP
# =============================
def get_real_ip():
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        return cf_ip
    return request.remote_addr

# =============================
# 密码
# =============================
def verify_password(db_password, input_password):
    if db_password.startswith(("pbkdf2:", "scrypt:")):
        return check_password_hash(db_password, input_password)
    old_hash = hashlib.sha256(input_password.encode()).hexdigest()
    return old_hash == db_password

# =============================
# Flask初始化
# =============================
app = Flask(
    __name__,
    template_folder=resource_path("templates"),
    static_folder=resource_path("static")
)

app.secret_key = config["flask"]["secret_key"]
app.logger.propagate = False

app.config.update(
    SESSION_COOKIE_HTTPONLY = True,
    SESSION_COOKIE_SECURE = True,
    SESSION_COOKIE_SAMESITE = "Lax"
)

# =============================
# IP访问记录
# =============================
IP_HISTORY = {}
MAX_DIRECT_IP_REQUESTS = 5
DIRECT_IP_WINDOW_SECONDS = 3600

# =============================
# 安全配置
# =============================
MAX_SECURITY_EVENTS = 30
MAX_LOGIN_FAIL = 5

BLACKLIST = {}
LOGIN_FAIL = {}
ATTACK_STATS = {}

BAN_DURATIONS = {
    "1天": 86400,
    "7天": 604800,
    "30天": 2592000,
    "永久": -1
}

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def check_user_ban_status(account):
    cur = mysql.connection.cursor()
    cur.execute("SELECT ban_status, ban_expire, ban_reason FROM sys_users WHERE account=%s", (account,))
    res = cur.fetchone()
    cur.close()
    if not res:
        return False, ""
    ban_status, ban_expire, ban_reason = res
    if ban_status == 0:
        return False, ""
    if ban_expire != -1 and time.time() > ban_expire:
        cur = mysql.connection.cursor()
        cur.execute("UPDATE sys_users SET ban_status=0, ban_expire=0, ban_reason='', ban_by='' WHERE account=%s",
                    (account,))
        mysql.connection.commit()
        cur.close()
        return False, ""
    if ban_expire == -1:
        expire_str = "永久封禁"
    else:
        remain = ban_expire - time.time()
        days = int(remain // 86400)
        hours = int((remain % 86400) // 3600)
        expire_str = f"剩余{days}天{hours}小时"
    return True, f"账户被封禁：{ban_reason}（{expire_str}）"

def check_page_access(account, page):
    cur = mysql.connection.cursor()
    cur.execute("SELECT role, allowed_pages FROM sys_users WHERE account=%s", (account,))
    res = cur.fetchone()
    cur.close()
    if not res:
        return False
    role, allowed_pages = res
    if role in ["admin", "super_admin"]:
        return True
    allowed = allowed_pages.split(",") if allowed_pages else []
    return page in allowed

def load_attack_stats():
    global ATTACK_STATS
    if os.path.exists(ATTACK_STATS_FILE):
        try:
            with open(ATTACK_STATS_FILE, "r", encoding="utf-8") as f:
                ATTACK_STATS = json.load(f)
        except:
            ATTACK_STATS = {}
    else:
        ATTACK_STATS = {}
        save_attack_stats()

def save_attack_stats():
    try:
        with open(ATTACK_STATS_FILE + ".tmp", "w", encoding="utf-8") as f:
            json.dump(ATTACK_STATS, f, ensure_ascii=False, indent=2)
        os.replace(ATTACK_STATS_FILE + ".tmp", ATTACK_STATS_FILE)
    except:
        pass

def load_blacklist():
    global BLACKLIST
    if os.path.exists(BLACKLIST_FILE):
        try:
            with open(BLACKLIST_FILE, "r", encoding="utf-8") as f:
                BLACKLIST = json.load(f)
        except:
            BLACKLIST = {}

load_attack_stats()
load_blacklist()
init_ip_cache_system()

def save_blacklist():
    try:
        with open(BLACKLIST_FILE + ".tmp", "w", encoding="utf-8") as f:
            json.dump(BLACKLIST, f, ensure_ascii=False, indent=2)
        os.replace(BLACKLIST_FILE + ".tmp", BLACKLIST_FILE)
    except:
        pass

def ban_ip(ip, reason="malicious", permanent=False):
    if permanent:
        expire = -1
        expire_str = "永久封禁"
    else:
        expire = int(time.time()) + config["security"]["ban_duration"]
        expire_str = datetime.fromtimestamp(expire).strftime('%Y-%m-%d %H:%M:%S')
    BLACKLIST[ip] = {"expire": expire, "reason": reason}
    save_blacklist()
    log_action("自动封禁IP", f"原因:{reason} | 过期:{expire_str}", "WARNING", True, 403)

# =============================
# 限速
# =============================
limiter = Limiter(get_real_ip, app=app, default_limits=["200 per minute"], storage_uri="memory://")
BAN_DURATION = config["security"]["ban_duration"]

# =============================
# 数据库
# =============================
app.config['MYSQL_HOST'] = config["mysql"]["host"]
app.config['MYSQL_USER'] = config["mysql"]["user"]
app.config['MYSQL_PASSWORD'] = config["mysql"]["password"]
app.config['MYSQL_DB'] = config["mysql"]["database"]
app.config['MYSQL_PORT'] = config["mysql"]["port"]
mysql = MySQL(app)

# =============================
# 日志（全局捕获所有报错 + 系统输出）
# =============================
if not os.path.exists("logs"):
    os.mkdir("logs")

# 1. 主日志处理器
handler = RotatingFileHandler("logs/system.log", maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
formatter = logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s")
handler.setFormatter(formatter)

# 2. 给 Flask app 日志
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)
app.logger.propagate = True

# 3. 捕获 root 日志（所有库、系统报错、未捕获异常全都走这里）
root_logger = logging.getLogger()
root_logger.addHandler(handler)
root_logger.setLevel(logging.INFO)

# =============================
# 攻击特征
# =============================
ATTACK_PATTERNS = [
    ".env", ".git", "phpunit", "wp-login", "wp-admin", "eval-stdin", "cgi-bin",
    "shell", "cmd=", "wget", "curl", "base64", "/etc/passwd", "../", "union select",
    "sleep(", "information_schema"
]

# =============================
# 日志函数（已集成地理位置）
# =============================
def log_action(action_type, detail="", level="INFO", security_event=False, status_code=200):
    # ===== 忽略统计API日志 =====
    IGNORE_LOG_PATHS = [
        "/api/attack_stats",
        "/api/ip_blacklist",
        "/api/get_current_user",
        "/api/real_time_log",
        "/api/query_ip"
    ]
    if request.path in IGNORE_LOG_PATHS:
        return

    action_padded = f"[{action_type}]".ljust(12)
    user = session.get("account", "未登录")
    ip = get_real_ip()
    location = get_ip_location(ip)

    msg = f"{action_padded} | 用户:{user} | IP:{ip} | 位置:{location} | 状态:{status_code} | 详情:{detail}"
    if level == "WARNING":
        app.logger.warning(msg)
    elif level == "ERROR":
        app.logger.error(msg)
    else:
        app.logger.info(msg)

    if security_event:
        global ATTACK_STATS
        ATTACK_STATS[ip] = ATTACK_STATS.get(ip, 0) + 1
        save_attack_stats()

# ===== 新增用户管理页面权限装饰器 =====
def check_user_manage_permission(func):
    """仅管理员/超级管理员可访问用户管理页面"""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        account = session.get("account")
        if not account:
            flash("请先登录")
            return redirect("/login")

        # 检查账户角色
        cur = mysql.connection.cursor()
        cur.execute("SELECT role FROM sys_users WHERE account=%s", (account,))
        res = cur.fetchone()
        cur.close()

        if not res or res[0] not in ["admin", "super_admin"]:
            flash("无用户管理权限！")
            return redirect("/")

        return func(*args, **kwargs)

    return wrapper

# =============================
# 请求检查（整合log_action，修复逻辑瑕疵）
# =============================
@app.before_request
def security_check():
    ip = get_real_ip()
    host = request.host.split(":")[0]
    client_ip = request.remote_addr  # 真实来源IP

    # =============================
    # 🔥 终极加固：只允许 Cloudflare / 本机访问
    # =============================
    if time.time() - LAST_REFRESH_TIME > REFRESH_INTERVAL:
        refresh_cloudflare_ips()

    # 非本机 且 非Cloudflare → 直接拒绝
    if client_ip not in ("127.0.0.1", "::1") and not is_cloudflare_ip(client_ip):
        return "Forbidden", 403

    if ATTACK_STATS.get(ip, 0) >= MAX_SECURITY_EVENTS and ip not in BLACKLIST:
        ban_ip(ip, reason="security_events_exceed_30", permanent=True)
        app.logger.critical(f"[永久封禁] IP:{ip} 累计安全事件达到{ATTACK_STATS[ip]}次，执行永久封禁")

    # 2. 黑名单检查（整合log_action，补充过期时间）
    if ip in BLACKLIST:
        expire_ts = BLACKLIST[ip]["expire"]
        if expire_ts == -1:
            expire_str = "永久封禁"
            # 永久封禁永远视为未过期
            is_expired = False
        else:
            try:
                expire_str = datetime.fromtimestamp(expire_ts).strftime("%Y-%m-%d %H:%M:%S")
                is_expired = time.time() >= expire_ts
            except:
                expire_str = "未知时间"
                is_expired = False

            # 未过期：拦截并记录日志
        if not is_expired:
            log_action(
                "黑名单拦截",
                f"操作:{request.method} {request.path} | 过期时间:{expire_str} | 原因:{BLACKLIST[ip]['reason']}",
                level="WARNING",
                security_event=False,
                status_code=403
            )
            return "Forbidden", 403
            # 已过期：自动解封
        else:
            del BLACKLIST[ip]
            save_blacklist()
            log_action("黑名单自动解封", f"IP:{ip} 封禁时间到期", level="INFO", status_code=200)

    # ===== 新增：拦截无用路径（替代Nginx配置）=====
    # 要拦截的路径正则（匹配/wp-content/、/images/、/fb/、/fwc/等）
    block_pattern = re.compile(r'/(wp-content|images|fb|fwc|fzh|aaabbbccc)/', re.IGNORECASE)
    # 匹配请求路径（只拦截GET请求，避免影响POST等业务请求）
    if request.method == 'GET' and block_pattern.search(request.path):
        # 记录拦截日志（可选，方便排查）
        log_action(
            "拦截无用路径",
            f"路径:{request.path} | 原因:匹配无用路径规则",
            level="INFO",
            status_code=404
        )
        return "Not Found", 404

    # 1. 禁止直接IP访问（修复：允许本地测试+兼容端口）
    # 本地环境（127.0.0.1/localhost）不限制，生产环境禁止IP直连
    is_local = host in ["127.0.0.1", "localhost"]
    is_ip_host = re.match(r"^\d+\.\d+\.\d+\.\d+$", host)
    if not is_local and is_ip_host:
        now = time.time()
        history = IP_HISTORY.get(ip, [])
        # 只保留窗口内访问记录
        history = [ts for ts in history if now - ts < DIRECT_IP_WINDOW_SECONDS]
        history.append(now)
        IP_HISTORY[ip] = history

        if len(history) > MAX_DIRECT_IP_REQUESTS:
            ban_ip(ip, "direct_ip_flood")
            log_action(
                "自动封禁IP",
                f"IP:{ip} 短时间直连次数过多 ({len(history)}次)",
                level="WARNING",
                security_event=True,
                status_code=403
            )
            return "Forbidden", 403

        log_action("禁止IP直连", f"IP:{ip} 访问主机:{host}", level="WARNING", security_event=True, status_code=403)
        return "Forbidden", 403

    # 3. 攻击特征检测（整合log_action，优化统计）
    path = request.full_path.lower()
    for pattern in ATTACK_PATTERNS:
        if pattern in path:
            # 攻击次数统计（可选：累计3次翻倍封禁）
            ATTACK_STATS[ip] = ATTACK_STATS.get(ip, 0) + 1
            save_attack_stats()
            ban_reason = "attack_scan" if ATTACK_STATS[ip] < 3 else "attack_scan_repeat"
            # 记录攻击日志 + 封禁IP
            log_action(
                "恶意路径拦截",
                f"特征:{pattern} | 路径:{request.full_path} | 累计攻击次数:{ATTACK_STATS[ip]}",
                level="WARNING",
                security_event=True,
                status_code=403
            )
            ban_ip(ip, ban_reason)
            return "Forbidden", 403

    # 4. 正常访问日志（统一用log_action）
    log_action(
        "正常访问",
        f"操作:{request.method} {request.path}",
        level="INFO",
        status_code=200
    )

# =============================
# 全局404错误处理（新增）
# =============================
@app.errorhandler(404)
def page_not_found(e):
    log_action(
        "页面不存在",
        f"操作:{request.method} {request.path}",
        level="WARNING",
        status_code=404
    )
    return "页面不存在", 404

# =============================
# 类型系统
# =============================
TYPE_CONFIG = {
    "新八开挂": {"visible": True},
    "老八开挂": {"visible": True},
    "演员": {"visible": True},
    "爷新": {"visible": True},
    "特殊": {"visible": True},
    "测试": {"visible": False}
}

VISIBLE_TYPES = [
    key for key, value in TYPE_CONFIG.items() if value["visible"]
]

ALLOWED_TYPES = set(TYPE_CONFIG.keys())

# =============================
# 工具函数
# =============================
def normalize_type(input_type: str):
    if not input_type:
        return None
    input_type = input_type.replace('\u3000', ' ').strip()
    input_type = re.sub(r'[\x00-\x1f\x7f]', '', input_type)
    return input_type

def extract_bv_from_url(url):
    """从B站链接中提取BV号，支持b23短链与长链接"""
    bv_pattern = re.compile(r'(BV[a-zA-Z0-9]{10})')
    match = bv_pattern.search(url)
    if match:
        return match.group(1)
    if 'b23.tv' in url:
        try:
            resp = requests.head(url, allow_redirects=False, timeout=5)
            real_url = resp.headers.get('Location', '')
            match = bv_pattern.search(real_url)
            if match:
                return match.group(1)
        except Exception as e:
            print(f"请求短链失败: {e}")
    return None

def is_valid_uuid(uuid_str):
    pattern = re.compile(
        r'^[0-9a-fA-F]{8}-'
        r'[0-9a-fA-F]{4}-'
        r'[0-9a-fA-F]{4}-'
        r'[0-9a-fA-F]{4}-'
        r'[0-9a-fA-F]{12}$'
    )
    return bool(pattern.match(uuid_str))

def check_date_not_exceed_today(date_str):
    try:
        input_date = datetime.strptime(date_str, "%Y-%m-%d").date()
        return input_date <= datetime.now().date()
    except:
        return False

def check_uuid_exists(uuid_str):
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT Name, Uuid, Type, Remark, Date FROM td2ban WHERE Uuid=%s",
        (uuid_str,)
    )
    data = cur.fetchall()
    cur.close()
    return data

def check_login(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect("/login")

        login_time = session.get("login_time")

        if login_time and time.time() - login_time > 7200:
            session.clear()
            flash("登录已超时")
            return redirect("/login")

        return func(*args, **kwargs)

    return wrapper

# =============================
# 权限控制（新增）
# =============================
def check_admin(func):
    """允许普通管理员+超级管理员访问（查看权限）"""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        account = session.get("account")
        if not account:
            flash("请先登录")
            return redirect("/login")

        # 从数据库查询角色（正确方式）
        cur = mysql.connection.cursor()
        cur.execute("SELECT role FROM sys_users WHERE account=%s", (account,))
        res = cur.fetchone()
        cur.close()

        # 角色是 admin 或 super_admin 都允许访问
        if not res or res[0] not in ["admin", "super_admin"]:
            flash("无管理员权限！")
            return redirect("/")

        return func(*args, **kwargs)

    return wrapper

def check_super_admin(func):
    """仅允许超级管理员访问（修复：读取数据库role，不读配置）"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        account = session.get("account")
        if not account:
            flash("请先登录")
            return redirect("/login")

        cur = mysql.connection.cursor()
        cur.execute("SELECT role FROM sys_users WHERE account=%s", (account,))
        res = cur.fetchone()
        cur.close()

        if not res or res[0] != "super_admin":
            flash("无超级管理员权限，无法执行此操作！")
            return redirect("/admin/ip_manage")
        return func(*args, **kwargs)
    return wrapper

# 新增页面访问检查装饰器
def check_page_permission(page):
    """检查用户是否有权访问指定页面"""

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            account = session.get("account")
            if not account:
                return redirect("/login")

            # 检查封禁状态
            is_banned, ban_msg = check_user_ban_status(account)
            if is_banned:
                flash(ban_msg)
                return redirect("/login")

            # 检查页面访问权限
            if not check_page_access(account, page):
                flash(f"无访问{page}页面的权限！")
                log_action("页面访问拦截", f"账号:{account} 页面:{page} 原因:无权限", level="WARNING", status_code=403)
                return redirect("/")

            return func(*args, **kwargs)

        return wrapper

    return decorator

@app.errorhandler(Exception)
def handle_global_exception(e):
    try:
        user = session.get("account", "未登录")
        ip = get_real_ip()
        location = get_ip_location(ip)
        err_msg = str(e)[:200]

        # 👇 这行是修复关键，直接用你原来的格式，不会破坏日志解析
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
        action_padded = "[文件报错]".ljust(12)
        msg = f"{now_str} | ERROR     | {action_padded} | 用户:{user} | IP:{ip} | 位置:{location} | 状态:500 | 详情:{err_msg}"
        app.logger.error(msg)
    except:
        pass

    return "服务器内部错误", 500

@app.route('/favicon.ico', methods=['GET'])
def favicon():
    # 返回空的ICO响应，避免404日志
    return "", 204  # 204 = 无内容，比404更友好

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/login_validation", methods=["POST"])
@limiter.limit("5 per minute")
def login_validation():
    ip = get_real_ip()

    if LOGIN_FAIL.get(ip, 0) >= MAX_LOGIN_FAIL:
        ban_ip(ip, "login_bruteforce")
        log_action("登录暴力破解拦截", f"IP:{ip} 失败次数≥{MAX_LOGIN_FAIL}", level="WARNING", security_event=True,
                   status_code=403)
        return "Forbidden", 403

    account = request.form.get("account", "").strip()
    password = request.form.get("password", "").strip()

    if not account or not password:
        flash("请输入账号和密码")
        log_action("登录失败", f"IP:{ip} 账号/密码为空", level="WARNING", status_code=400)
        return redirect("/login")

    # 检查账户是否被封禁
    is_banned, ban_msg = check_user_ban_status(account)
    if is_banned:
        flash(ban_msg)
        log_action("登录失败", f"账号:{account} IP:{ip} 原因:账户被封禁", level="WARNING", status_code=403)
        return redirect("/login")

    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT account,password,role FROM sys_users WHERE account=%s",
        (account,)
    )

    user = cur.fetchone()
    cur.close()

    if user and verify_password(user[1], password):

        # 如果是旧密码，自动升级
        if not user[1].startswith("pbkdf2:"):
            new_hash = generate_password_hash(password)

            cur2 = mysql.connection.cursor()
            cur2.execute(
                "UPDATE sys_users SET password=%s WHERE account=%s",
                (new_hash, account)
            )
            mysql.connection.commit()
            cur2.close()

        session["logged_in"] = True
        session["login_time"] = time.time()
        session["account"] = account
        session["role"] = user[2]
        session["is_super_admin"] = user[2] == "super_admin"

        LOGIN_FAIL.pop(ip, None)

        log_action("登录成功", f"账号:{account} IP:{ip} 角色:{user[2]}", level="INFO", status_code=200)
        flash("登录成功")
        return redirect("/")

    else:
        LOGIN_FAIL[ip] = LOGIN_FAIL.get(ip, 0) + 1
        log_action("登录失败", f"账号:{account} IP:{ip} 失败次数:{LOGIN_FAIL[ip]}", level="WARNING",
                   security_event=True, status_code=401)
        flash("账号或密码错误")
        return redirect("/login")

# =============================
# 登录页面
# =============================
@app.route("/login")
def login():
    if session.get("logged_in"):
        return redirect("/")
    return render_template("login.html")

# =============================
# 首页
# =============================
@app.route("/")
@check_login
def index():
    # ========== 修复：从session获取正确的角色 ==========
    current_role = session.get("role", "normal")
    is_admin = current_role in ["admin", "super_admin"]
    is_super_admin = current_role == "super_admin"
    # ==================================================

    # 渲染模板并添加缓存控制响应头
    response = make_response(render_template("index.html", is_admin=is_admin, is_super_admin=is_super_admin))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# =============================
# 登记页面
# =============================
@app.route("/record")
@check_login
@check_page_permission("record.html")
def record():
    if "token" not in session:
        session["token"] = os.urandom(16).hex()

    # ========== 修复：从session获取正确的角色 ==========
    current_role = session.get("role", "normal")
    is_super_admin = (current_role == "super_admin")
    is_admin = (current_role == "admin")
    # ==================================================

    return render_template(
        "record.html",
        token=session["token"],
        allowed_types=VISIBLE_TYPES,
        form_data=session.pop("form_data", {}),
        today=datetime.now().strftime("%Y-%m-%d"),
        is_super_admin=is_super_admin,
        is_admin=is_admin
    )

# =============================
# 查询页面
# =============================
@app.route("/search")
@check_login
@check_page_permission("search.html")
def search():
    query = request.args.get("q", "").strip()
    search_type = request.args.get("type", "name")

    cur = mysql.connection.cursor()

    if not query:
        cur.execute(
            "SELECT Name,Uuid,Type,Remark,Date FROM td2ban ORDER BY Date DESC"
        )
    else:
        if search_type == "uuid":
            if not is_valid_uuid(query):
                flash("UUID格式错误")
                log_action("查询失败", f"UUID格式错误: {query}", level="WARNING", status_code=400)
                return redirect("/search")

            cur.execute(
                "SELECT Name,Uuid,Type,Remark,Date FROM td2ban WHERE Uuid=%s",
                (query,)
            )
        elif search_type == "name":
            cur.execute(
                "SELECT Name,Uuid,Type,Remark,Date FROM td2ban WHERE Name LIKE %s",
                (f"%{query}%",)
            )
        elif search_type == "type":
            cur.execute(
                "SELECT Name,Uuid,Type,Remark,Date FROM td2ban WHERE Type=%s",
                (query,)
            )

    data = cur.fetchall()
    cur.close()

    # ========== 修复：从session获取正确的角色 ==========
    current_role = session.get("role", "normal")
    is_super_admin = (current_role == "super_admin")
    is_admin = (current_role == "admin")
    # ==================================================

    return render_template("search.html", data=data, is_super_admin=is_super_admin, is_admin=is_admin)

# =============================
# 提交页面
# =============================
@app.route("/submit", methods=["POST"])
@check_login
def submit():
    if session.get("token") != request.form.get("token"):
        flash("非法请求")
        log_action("提交失败", "Token验证失败", level="WARNING", status_code=403)
        return redirect("/record")

    name = request.form.get("name", "").strip()
    uuid_str = request.form.get("uuid", "").strip()
    type_value = normalize_type(request.form.get("type"))
    date_str = request.form.get("date", "").strip()
    remark = request.form.get("remark", "").strip()
    video_link = request.form.get("video_link", "").strip()

    session["form_data"] = request.form.to_dict()

    if type_value not in ALLOWED_TYPES:
        flash("作案类型非法")
        log_action("提交失败", f"非法类型: {type_value}", level="WARNING", status_code=400)
        return redirect("/record")

    if not is_valid_uuid(uuid_str):
        flash("UUID 格式无效")
        log_action("提交失败", f"UUID格式错误: {uuid_str}", level="WARNING", status_code=400)
        return redirect("/record")

    if not check_date_not_exceed_today(date_str):
        flash("日期不能超过当天")
        log_action("提交失败", f"日期超出限制: {date_str}", level="WARNING", status_code=400)
        return redirect("/record")


    if video_link :
        bv = extract_bv_from_url(video_link)
        if bv:
            final_url = f"https://www.bilibili.com/video/{bv}/"
        else:
            # 不是B站链接，直接使用原始链接
            final_url = video_link

        # 按要求格式拼接：空格 + [视频证据](链接)
        remark = f"{remark} [视频证据]({final_url})"

    existing_data = check_uuid_exists(uuid_str)
    if existing_data:
        log_action("重复UUID提交", uuid_str, level="WARNING", status_code=409)
        return render_template(
            "show_existing_data.html",
            data=existing_data,
            new_data={
                "name": name,
                "uuid": uuid_str,
                "type": type_value,
                "date": date_str,
                "remark": remark
            }
        )

    try:
        date_obj = datetime.strptime(date_str, "%Y-%m-%d").date()

        cur = mysql.connection.cursor()
        cur.execute(
            "INSERT INTO td2ban (Name, Uuid, Type, Remark, Date) VALUES (%s,%s,%s,%s,%s)",
            (name, uuid_str, type_value, remark, date_obj)
        )
        mysql.connection.commit()
        cur.close()

        session.pop("form_data", None)

        log_action("正常提交", f"{name} | {uuid_str}", level="INFO", status_code=200)
        flash("提交成功")
        return redirect("/record")

    except Exception as e:
        mysql.connection.rollback()
        log_action("提交失败", str(e), level="ERROR", status_code=500)
        flash("提交失败")
        return redirect("/record")

# =============================
# 强制提交页面
# =============================
@app.route("/continue_submit", methods=["POST"])
@check_login
def continue_submit():
    name = request.form.get("name", "").strip()
    uuid_str = request.form.get("uuid", "").strip()
    type_value = normalize_type(request.form.get("type"))
    date_str = request.form.get("date", "").strip()
    remark = request.form.get("remark", "").strip()

    try:
        date_obj = datetime.strptime(date_str, "%Y-%m-%d").date()

        cur = mysql.connection.cursor()
        cur.execute(
            "INSERT INTO td2ban (Name, Uuid, Type, Remark, Date) VALUES (%s,%s,%s,%s,%s)",
            (name, uuid_str, type_value, remark, date_obj)
        )
        mysql.connection.commit()
        cur.close()

        session.pop("form_data", None)

        log_action("强制提交", f"{name} | {uuid_str}", level="INFO", status_code=200)
        flash("提交成功")
        return redirect("/record")

    except Exception as e:
        mysql.connection.rollback()
        log_action("强制提交失败", str(e), level="ERROR", status_code=500)
        flash("提交失败")
        return redirect("/record")

# =============================
# 后台管理页面 - IP黑名单管理
# =============================
@app.route("/admin/ip_manage")
@check_login
@check_admin
def admin_ip_manage():
    # 传递用户角色给前端
    is_super_admin = session.get("is_super_admin", False)
    return render_template("ip_manage.html", is_super_admin=is_super_admin)

# =============================
# 用户管理页面
# =============================
@app.route("/admin/user_manage")
@check_login
@check_user_manage_permission
def admin_user_manage():
    """用户管理页面"""
    current_account = session.get("account")
    # 获取当前用户角色
    cur = mysql.connection.cursor()
    cur.execute("SELECT role FROM sys_users WHERE account=%s", (current_account,))
    current_role = cur.fetchone()[0]
    cur.close()

    # 🔥 加这一行：判断是否是最高权限
    is_root_admin = current_account in ROOT_SUPER_ADMINS

    return render_template("user_manage.html",
                           current_account=current_account,
                           current_role=current_role,
                           is_super_admin=session.get("is_super_admin", False),
                           is_root_admin=is_root_admin)

# ============ API类 =================

# =============================
# 手动解封IP接口
# =============================
@app.route("/api/unban_ip", methods=["POST"])
@check_login
@check_super_admin
def unban_ip():
    ip = request.form.get("ip", "").strip()
    if not ip:
        log_action("手动解封IP失败", "IP参数为空", level="WARNING", status_code=400)
        return jsonify({"status": "fail", "msg": "IP不能为空"})

    if ip in BLACKLIST:
        # 新增↓↓↓ 先判断该IP是否为永久封禁
        is_permanent = BLACKLIST[ip]["expire"] == -1
        # 新增↑↑↑

        del BLACKLIST[ip]
        save_blacklist()

        # 修改↓↓↓ 仅永久封禁的IP解封时才清空安全次数
        if is_permanent and ip in ATTACK_STATS:
            del ATTACK_STATS[ip]
            save_attack_stats()
            # 补充日志：标记清空了统计次数
            log_action("手动解封IP", f"IP:{ip}（永久封禁），已清空安全事件次数", level="WARNING", status_code=200)
        else:
            log_action("手动解封IP", f"IP:{ip}（临时封禁），保留安全事件次数", level="WARNING", status_code=200)
        # 修改↑↑↑

        return jsonify({"status": "ok", "msg": f"已解封 {ip}"})
    else:
        log_action("手动解封IP失败", f"IP:{ip} 不在黑名单中", level="WARNING", status_code=404)
        return jsonify({"status": "fail", "msg": "该IP不在黑名单中"})

# ==============================
# IP 地址查询 接口
# ==============================
@app.route("/api/query_ip", methods=["POST"])
@check_login
@check_admin
def api_query_ip():
    ip = request.form.get("ip", "").strip()
    if not ip:
        return jsonify({"status": "fail"})

    # 直接从缓存拿，0 查询
    if ip in ip_location_cache:
        return jsonify(ip_location_cache[ip])

    # 不存在才查（极少触发）
    country, prov, city, isp, is_dc = get_ip_detail(ip)
    typ = get_ip_display_type(isp)
    data = {
        "status": "ok",
        "country": country,
        "province": prov,
        "city": city,
        "isp": isp,
        "type": typ
    }
    ip_location_cache[ip] = data
    save_ip_cache()
    return jsonify(data)

# ==============================
# 实时安全日志接口
# ==============================
@app.route("/api/real_time_log")
@check_login
@check_admin
def real_time_log():
    log_path = os.path.join(os.getcwd(), "logs", "system.log")

    if not os.path.exists(log_path):
        return jsonify([])

    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except:
        return jsonify([])

    lines = lines[-50:]
    logs = []

    log_pattern = re.compile(
        r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+'
        r'\s*\|\s*([A-Z]+)'
        r'\s*\|\s*(\[.+?\])'
        r'\s*\|\s*用户:(.+?)'
        r'\s*\|\s*IP:(.+?)'
        r'\s*\|\s*位置:(.+?)'
        r'\s*\|\s*状态:(\d+)'
        r'\s*\|\s*详情:(.+)$'
    )

    for line in lines:
        line = line.strip()
        if not line:
            continue

        match = log_pattern.match(line)
        if not match:
            continue

        log_time = match[1].strip()
        level = match[2].strip()
        action = match[3].strip()
        user = match[4].strip()
        ip = match[5].strip()
        location = match[6].strip()
        status_code = match[7].strip()
        detail = match[8].strip()

        # 日志内容精简
        msg = f"{action} | {detail}"

        # 🔥 文字改成：高危 / 低危 / 安全
        if level == "ERROR":
            log_level = "high"
            level_text = "风险"
        elif level == "WARNING":
            log_level = "high"
            level_text = "风险"
        else:
            log_level = "low"
            level_text = "安全"

        logs.append({
            "time": log_time,
            "ip": ip,
            "msg": msg,
            "level": log_level,
            "level_text": level_text,
            "user": user,
            "location": location,
            "status_code": status_code
        })

    return jsonify(logs[::-1])

# ==============================
# 攻击统计 / 安全风险统计接口
# ==============================
@app.route("/api/attack_stats")
@check_login
@check_admin
def api_attack_stats():
    load_attack_stats()  # 重新加载最新数据
    data = []
    for ip, count in ATTACK_STATS.items():
        data.append({
            "ip": ip,
            "event_count": count,
            "risk_level": "高风险" if count >= 15 else "中风险" if count >= 5 else "低风险"
        })
    data.sort(key=lambda x: x["event_count"], reverse=True)

    response = jsonify(data)
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# ==============================
# 获取所有用户列表接口
# ==============================
@app.route("/api/get_all_users")
@check_login
@check_user_manage_permission
def get_all_users():
    current_account = session.get("account")
    cur = mysql.connection.cursor()

    cur.execute("""
                SELECT account, role, allowed_pages, ban_status, ban_expire, ban_reason, ban_by
                FROM sys_users
                """)

    users_raw = cur.fetchall()

    users = []
    for row in users_raw:
        account, role, allowed_pages, ban_status, ban_expire, ban_reason, ban_by = row
        # 处理封禁过期时间
        if ban_expire == -1:
            expire_str = "永久封禁"
        elif ban_expire == 0:
            expire_str = "未封禁"
        else:
            if time.time() > ban_expire:
                expire_str = "已过期（待自动解封）"
            else:
                days = int((ban_expire - time.time()) // 86400)
                hours = int(((ban_expire - time.time()) % 86400) // 3600)
                expire_str = f"{days}天{hours}小时"

        # 修复：处理allowed_pages为None/空字符串，统一转成数组
        if allowed_pages is None or allowed_pages == "":
            allowed_pages_list = []
        else:
            allowed_pages_list = allowed_pages.split(",")

        users.append({
            "account": account,
            "role": role,  # 保持role字段不变
            "role_name": {"normal": "普通用户", "admin": "管理员", "super_admin": "超级管理员"}[role],
            "allowed_pages": allowed_pages_list,  # 确保是数组
            "ban_status": ban_status,
            "ban_expire": expire_str,
            "ban_reason": ban_reason,
            "ban_by": ban_by
        })
    cur.close()
    return jsonify(users)

# ==============================
# 添加用户接口
# ==============================
@app.route("/api/add_user", methods=["POST"])
@check_login
@check_user_manage_permission
def add_user():
    account = request.form.get("account", "").strip()
    password = request.form.get("password", "").strip()
    role = request.form.get("role", "normal")
    allowed_pages = request.form.getlist("allowed_pages[]")

    if not account or not password:
        return jsonify({"status": "fail", "msg": "账号/密码不能为空"})

    # 普通管理员只能添加普通用户
    current_account = session.get("account")
    cur = mysql.connection.cursor()
    cur.execute("SELECT role FROM sys_users WHERE account=%s", (current_account,))
    current_role = cur.fetchone()[0]
    if current_role == "admin" and role != "normal":
        cur.close()
        return jsonify({"status": "fail", "msg": "普通管理员仅能添加普通用户"})

    # 🔒 只有 root_super_admin 列表内的账号才能创建超级管理员
    is_root_admin = current_account in ROOT_SUPER_ADMINS
    if role == "super_admin" and not is_root_admin:
        cur.close()
        return jsonify({
            "status": "fail",
            "msg": "只有最高管理员才能创建超级管理员"
        })

    # 检查账号是否已存在
    cur.execute("SELECT 1 FROM sys_users WHERE account=%s", (account,))
    if cur.fetchone():
        cur.close()
        return jsonify({"status": "fail", "msg": "账号已存在"})

    # 插入新用户
    hashed_pwd = generate_password_hash(password)
    allowed_pages_str = ",".join(allowed_pages) if allowed_pages else ""
    cur.execute("""
                INSERT INTO sys_users (account, password, role, allowed_pages)
                VALUES (%s, %s, %s, %s)
                """, (account, hashed_pwd, role, allowed_pages_str))
    mysql.connection.commit()
    cur.close()

    log_action("添加用户", f"创建账号:{account} 角色:{role}", level="INFO", status_code=200)
    return jsonify({"status": "ok", "msg": "用户创建成功"})

# ==============================
# 封禁用户接口
# ==============================
@app.route("/api/ban_user", methods=["POST"])
@check_login
@check_user_manage_permission
def ban_user():
    target_account = request.form.get("account", "").strip()
    ban_type = request.form.get("ban_type", "")
    ban_expire_str = request.form.get("ban_expire", "")
    ban_reason = request.form.get("ban_reason", "").strip()
    current_account = session.get("account")

    if not target_account or not ban_type or not ban_reason:
        return jsonify({"status": "fail", "msg": "参数不能为空"})

    cur = None
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT role FROM sys_users WHERE account=%s", (current_account,))
        current_role = cur.fetchone()[0]

        cur.execute("SELECT role, ban_by FROM sys_users WHERE account=%s", (target_account,))
        user_data = cur.fetchone()
        if not user_data:
            return jsonify({"status": "fail", "msg": "目标用户不存在"})
        target_role, ban_by = user_data

        if target_role == "super_admin":
            log_action("封禁用户失败", f"尝试封禁超级管理员:{target_account}", level="WARNING", status_code=403)
            return jsonify({"status": "fail", "msg": "超级管理员无法被封禁！"})

        if target_account == current_account:
            log_action("封禁用户失败", f"用户{current_account}尝试封禁自己", level="WARNING", status_code=403)
            return jsonify({"status": "fail", "msg": "无法封禁当前登录的自己！"})

        if current_role == "admin" and target_role in ["admin", "super_admin"]:
            return jsonify({"status": "fail", "msg": "普通管理员不能封禁管理员/超级管理员"})

        if current_role == "admin":
            if ban_by is None or ban_by == "":
                pass
            elif ban_by != current_account:
                return jsonify({"status": "error", "msg": "仅能修改自己封禁的用户！"})

        if ban_type == "永久":
            ban_expire = -1
        elif ban_type == "自定义日期":
            try:
                expire_date = datetime.strptime(ban_expire_str, "%Y-%m-%d")
                ban_expire = int(expire_date.timestamp())
                if ban_expire < int(time.time()):
                    return jsonify({"status": "fail", "msg": "自定义封禁日期不能早于当前时间"})
            except ValueError:
                return jsonify({"status": "fail", "msg": "自定义日期格式错误（应为YYYY-MM-DD）"})
        else:
            if ban_type not in BAN_DURATIONS:
                return jsonify({"status": "fail", "msg": "无效的封禁时长类型"})
            ban_expire = int(time.time()) + BAN_DURATIONS[ban_type]

        cur.execute("""
                    UPDATE sys_users
                    SET ban_status=1,
                        ban_expire=%s,
                        ban_reason=%s,
                        ban_by=%s
                    WHERE account = %s
                    """, (ban_expire, ban_reason, current_account, target_account))
        mysql.connection.commit()

        log_action("封禁用户", f"封禁账号:{target_account} 类型:{ban_type} 原因:{ban_reason}",
                   level="WARNING", status_code=200)
        return jsonify({"status": "ok", "msg": f"已封禁用户 {target_account}"})

    except Exception as e:
        if mysql.connection:
            mysql.connection.rollback()
        log_action("封禁用户失败", f"目标账号:{target_account} 错误:{str(e)}",
                   level="ERROR", status_code=500)
        return jsonify({"status": "fail", "msg": f"封禁失败：{str(e)}"})
    finally:
        if cur:
            cur.close()

# ==============================
# 解封用户接口
# ==============================
@app.route("/api/unban_user", methods=["POST"])
@check_login
@check_user_manage_permission
def unban_user():
    target_account = request.form.get("account", "").strip()
    current_account = session.get("account")

    if not target_account:
        return jsonify({"status": "fail", "msg": "目标账号不能为空"})

    cur = mysql.connection.cursor()
    cur.execute("SELECT ban_by, role FROM sys_users WHERE account=%s", (target_account,))
    res = cur.fetchone()
    if not res:
        cur.close()
        return jsonify({"status": "fail", "msg": "目标用户不存在"})
    ban_by, target_role = res

    cur.execute("SELECT role FROM sys_users WHERE account=%s", (current_account,))
    current_role = cur.fetchone()[0]

    if current_role == "admin":
        if ban_by != current_account or target_role != "normal":
            cur.close()
            return jsonify({"status": "fail", "msg": "仅能解封自己封禁的普通用户"})

    cur.execute("""
                UPDATE sys_users
                SET ban_status=0,
                    ban_expire=0,
                    ban_reason='',
                    ban_by=''
                WHERE account = %s
                """, (target_account,))
    mysql.connection.commit()
    cur.close()

    log_action("解封用户", f"解封账号:{target_account}", level="INFO", status_code=200)
    return jsonify({"status": "ok", "msg": f"已解封用户 {target_account}"})

# ==============================
# 调整用户角色接口
# ==============================
@app.route("/api/change_user_role", methods=["POST"])
@check_login
@check_admin  # 保留，允许普通管理员进入
def change_user_role():
    current_account = session.get("account")
    is_root_admin = current_account in ROOT_SUPER_ADMINS
    current_role = session.get("role")

    account = request.form.get("account")
    new_role = request.form.get("new_role")
    new_password = request.form.get("new_password", "").strip()
    allowed_pages = request.form.getlist("allowed_pages[]")

    is_modifying_self = (account == current_account)

    # ==============================================
    # 🔥 加固 1：普通管理员 绝对不能改密码
    # ==============================================
    if current_role == "admin" and new_password:
        return jsonify({
            "status": "error",
            "msg": "普通管理员无权修改密码！"
        })

    # ==============================================
    # 🔥 加固 2：普通管理员 只能修改普通用户，不能改角色
    # ==============================================
    cur = mysql.connection.cursor()
    cur.execute("SELECT role FROM sys_users WHERE account=%s", (account,))
    target_user = cur.fetchone()
    if not target_user:
        cur.close()
        return jsonify({"status": "error", "msg": "用户不存在"})
    target_role = target_user[0]

    # ==============================================
    # 🔥 核心加固：超级管理员之间不能互相修改
    # ==============================================
    if current_role == "super_admin":
        # 如果目标是超级管理员，并且不是修改自己 → 禁止操作
        if target_role == "super_admin" and not is_modifying_self:
            return jsonify({
                "status": "error",
                "msg": "超级管理员无法修改其他超级管理员！"
            })

    # 普通管理员只能操作普通用户
    if current_role == "admin":
        if target_role != "normal":
            cur.close()
            return jsonify({
                "status": "error",
                "msg": "普通管理员只能修改普通用户！"
            })

        # 🔥 强制不能改角色
        if new_role and new_role != "normal":
            return jsonify({
                "status": "error",
                "msg": "普通管理员不能修改角色！"
            })

        # 必须选择页面权限
        if not allowed_pages:
            return jsonify({
                "status": "error",
                "msg": "请选择至少一个可访问页面！"
            })

    # ==============================================
    # 超级管理员权限保留不变
    # ==============================================
    if current_role == "super_admin":
        if new_role == "super_admin" and not is_root_admin:
            return jsonify({
                "status": "error",
                "msg": "只有最高管理员可设置超级管理员"
            })

    # ==============================================
    # 最终执行：只更新页面权限
    # ==============================================
    try:
        # 普通管理员 → 只更新页面权限
        if current_role == "admin":
            pages_str = ",".join(allowed_pages)
            cur.execute("""
                UPDATE sys_users
                SET allowed_pages = %s
                WHERE account = %s
            """, (pages_str, account))

        # 超级管理员 → 可更新角色+权限+密码
        else:
            if new_role:
                if new_role in ["admin", "super_admin"]:
                    # 管理员/超级管理员 清空页面权限（系统自动全权限）
                    cur.execute("""
                        UPDATE sys_users
                        SET role = %s, allowed_pages = ''
                        WHERE account = %s
                        """, (new_role, account))
                else:
                    # 普通用户，正常设置角色
                    cur.execute("UPDATE sys_users SET role = %s WHERE account = %s", (new_role, account))

            if new_password:
                if target_role == "super_admin" and not is_modifying_self:
                    return jsonify({
                        "status": "error",
                        "msg": "禁止修改其他超级管理员的密码！"
                    })
                hashed_pwd = generate_password_hash(new_password)
                cur.execute("UPDATE sys_users SET password = %s WHERE account = %s", (hashed_pwd, account))

            if new_role == "normal":
                pages_str = ",".join(allowed_pages)
                cur.execute("UPDATE sys_users SET allowed_pages = %s WHERE account = %s", (pages_str, account))

        mysql.connection.commit()
        cur.close()

        log_action("修改用户权限", f"账号:{account}", status_code=200)
        return jsonify({"status": "ok", "msg": "权限保存成功"})

    except Exception as e:
        mysql.connection.rollback()
        cur.close()
        return jsonify({"status": "error", "msg": f"保存失败：{str(e)}"})

# ==============================
# 删除用户接口
# ==============================
@app.route("/api/delete_user", methods=["POST"])
@check_login
@check_super_admin
def delete_user():
    target_account = request.form.get("account", "").strip()
    current_account = session.get("account")

    if not target_account:
        log_action("删除用户失败", "目标账号为空", level="ERROR", status_code=400)
        return jsonify({"status": "fail", "msg": "目标账号不能为空"})

    if target_account == current_account:
        log_action("删除用户失败", f"超级管理员{current_account}尝试删除自己", level="ERROR", status_code=403)
        return jsonify({"status": "fail", "msg": "禁止删除当前登录的账户！"})

    cur = mysql.connection.cursor()
    try:
        cur.execute("SELECT role FROM sys_users WHERE account=%s", (target_account,))
        user_data = cur.fetchone()

        if not user_data:
            log_action("删除用户失败", f"目标账号{target_account}不存在", level="WARNING", status_code=404)
            return jsonify({"status": "fail", "msg": "目标用户不存在"})

        target_role = user_data[0]
        if target_role == "super_admin":
            log_action("删除用户失败", f"尝试删除超级管理员:{target_account}", level="CRITICAL", status_code=403)
            return jsonify({"status": "fail", "msg": "禁止删除超级管理员账户！"})

        cur.execute("DELETE FROM sys_users WHERE account=%s", (target_account,))
        mysql.connection.commit()

        log_action("删除用户", f"超级管理员{current_account}删除账号:{target_account}",
                   level="WARNING", security_event=True, status_code=200)
        return jsonify({"status": "ok", "msg": f"账户{target_account}已永久删除"})

    except mysql.connection.Error as e:
        mysql.connection.rollback()
        log_action("删除用户失败", f"目标账号:{target_account} 数据库错误:{str(e)}",
                   level="ERROR", status_code=500)
        return jsonify({"status": "fail", "msg": f"删除失败：数据库错误 - {str(e)}"})
    except Exception as e:
        mysql.connection.rollback()
        log_action("删除用户失败", f"目标账号:{target_account} 未知错误:{str(e)}",
                   level="ERROR", status_code=500)
        return jsonify({"status": "fail", "msg": f"删除失败：{str(e)}"})
    finally:
        if cur:
            cur.close()

# ==============================
# 获取当前登录用户信息接口
# ==============================
@app.route("/api/get_current_user")
@check_login
def get_current_user():
    account = session.get("account")
    cur = mysql.connection.cursor()
    cur.execute("""
                SELECT role, allowed_pages
                FROM sys_users
                WHERE account = %s
                """, (account,))
    row = cur.fetchone()
    cur.close()

    if not row:
        return jsonify({"status": "error", "msg": "用户不存在"}), 401

    role, allowed_pages = row
    allowed_pages_list = allowed_pages.split(",") if allowed_pages and allowed_pages.strip() else []

    return jsonify({
        "account": account,
        "role": role,
        "allowed_pages": allowed_pages_list
    })

# =============================
# IP 黑名单接口
# =============================
@app.route("/api/ip_blacklist")
@check_login
@check_admin
def api_blacklist():
    load_blacklist()
    data = []
    for ip, info in BLACKLIST.items():
        expire_ts = info["expire"]
        if expire_ts == -1:
            expire_str = "永久封禁"
        else:
            try:
                expire_str = datetime.fromtimestamp(expire_ts).strftime("%Y-%m-%d %H:%M:%S")
            except:
                expire_str = "未知时间"

        data.append({
            "ip": ip,
            "expire": expire_str,
            "reason": info["reason"]
        })

    response = jsonify(data)
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'

    return response

# =============================
# 缓存 IP 地理位置库接口
# =============================
@app.route("/api/all_ip_locations")
@check_login
@check_admin
def api_all_ip_locations():
    return jsonify(ip_location_cache)

# =============================
# TD2 黑名单成员接口
# =============================
@app.route("/api/all_bans")
@check_login
@limiter.limit("30 per minute")
def api_all_bans():
    cur = mysql.connection.cursor()
    cur.execute("""
                SELECT Name, Uuid, Type, Remark, Date
                FROM td2ban
                ORDER BY Date DESC
                """)

    rows = cur.fetchall()
    cur.close()

    data = []
    for r in rows:
        remark = r[3] or ""
        video = None
        m = re.search(r'\[视频证据\]\((.*?)\)', remark)

        if m:
            video = m.group(1)
            remark = re.sub(r'\[视频证据\]\(.*?\)', '', remark)

        data.append({
            "Name": r[0],
            "Uuid": r[1],
            "Type": r[2],
            "Remark": remark.strip(),
            "Date": str(r[4]),
            "Video": video
        })

    return jsonify(data)

# =============================
# 安全头
# =============================
@app.after_request
def add_security_headers(response):
    response.headers['X-Robots-Tag'] = 'noindex, nofollow'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'

    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:;"
    )

    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'

    return response

# =============================
# robots
# =============================
@app.route('/robots.txt')
@app.route('/robots')
def robots_txt():
    log_action("Robots协议访问", f"路径:{request.path}", level="INFO", status_code=200)
    return app.send_static_file('robots.txt')

# =============================
# 启动
# =============================
if __name__ == "__main__":
    try:
        serve(
            app,
            host="0.0.0.0",
            port=80,
            threads=8
        )
    except Exception as e:
        app.logger.critical(f"服务器崩溃: {str(e)}", exc_info=True)