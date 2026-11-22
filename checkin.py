#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
2026 GLaDOS 自动签到 (异常监控与 Cookie 检测增强版)

功能：
- 全自动签到（兼容 2026 新版 glados.cloud API 与 gld:sess / koa:sess Cookie）
- 精准检测 Cookie 有效性、API 变更、网络异常与签到结果
- 异常时主动以非零状态码退出（sys.exit(1)），触发 GitHub Actions 失败重试与邮件告警
- 输出 GitHub Actions Job Summary（含账号状态、积分、剩余天数、异常诊断）
- 可选 PushPlus 微信推送
"""

import json
import os
import sys
from datetime import datetime
import requests

# Fix Windows Unicode Output
if sys.platform.startswith('win'):
    sys.stdout.reconfigure(encoding='utf-8')

# ================= 配置 =================

# 域名优先级：Cloud 第一
DOMAINS = [
    "https://glados.cloud",
    "https://glados.rocks",
    "https://glados.network",
]

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Content-Type': 'application/json;charset=UTF-8',
    'Accept': 'application/json, text/plain, */*',
}

# 剩余天数低于该值时在日志和 Summary 中提示续期（不触发失败红叉）
LOW_DAYS_WARN_THRESHOLD = 7

# ================= 工具函数 =================

def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {msg}")


def extract_cookie(raw: str):
    """提取 Cookie，兼容 gld:sess / koa:sess / Cookie-Editor / JSON / JWT 格式"""
    if not raw:
        return None
    raw = raw.strip()

    # 现代/旧版标准键值对格式 (gld:sess=xxx; gld:sess.sig=yyy 或 koa:sess=xxx; ...)
    if 'gld:sess=' in raw or 'koa:sess=' in raw or 'koa:sess.sig=' in raw:
        return raw

    # JSON
    if raw.startswith('{'):
        try:
            token = json.loads(raw).get('token')
            if token:
                return 'koa.sess=' + token
        except Exception:
            pass

    # JWT Token
    if raw.count('.') == 2 and '=' not in raw and len(raw) > 50:
        return 'koa:sess=' + raw

    # Standard
    return raw


def get_cookies():
    raw = os.environ.get("GLADOS_COOKIE", "")
    if not raw or not raw.strip():
        log("❌ 未配置 GLADOS_COOKIE 环境变量")
        return []

    sep = '\n' if '\n' in raw else '&'
    return [c for c in (extract_cookie(item) for item in raw.split(sep)) if c]


def is_auth_error(res, http_status=None):
    """判断是否为 Cookie 过期或未授权"""
    if http_status in (401, 403):
        return True
    if not isinstance(res, dict):
        return False
    code = res.get('code')
    msg = str(res.get('message', '')).lower()
    if code == -2:
        return True
    auth_keywords = ('unauthorized', 'login', 'not login', 'expired', 'invalid cookie', 'unauthenticated')
    return any(k in msg for k in auth_keywords)


def evaluate_checkin(res, http_status=None):
    """
    判定签到结果。
    返回: (is_success: bool, status_type: str, detail_msg: str)
    status_type 取值: 'OK' | 'COOKIE_EXPIRED' | 'API_CHANGED' | 'NETWORK_ERROR' | 'FAILED'
    """
    if is_auth_error(res, http_status):
        msg = res.get('message', f'HTTP {http_status}') if isinstance(res, dict) else f'HTTP {http_status}'
        return False, 'COOKIE_EXPIRED', f"Cookie 已过期或无效 ({msg})"

    if res is None:
        return False, 'NETWORK_ERROR', "所有域名均请求失败（网络超时或服务不可达）"

    if not isinstance(res, dict):
        return False, 'FAILED', f"返回格式异常: {res}"

    msg = str(res.get('message', '')).strip()
    msg_lower = msg.lower()
    code = res.get('code')

    # API 规则变更提示
    if 'please checkin via' in msg_lower:
        return False, 'API_CHANGED', f"GLaDOS 签到接口/Token 已变更: {msg}"

    # 明确错误关键词
    error_keywords = ('fail', 'error', 'invalid', 'denied', 'forbidden')
    if any(k in msg_lower for k in error_keywords):
        return False, 'FAILED', msg or f"签到失败 (code={code})"

    # 成功判定：code == 0（本次签到成功）或 code == 1（今日已签）
    if code in (0, 1):
        return True, 'OK', msg or ('Checkin succeeded' if code == 0 else 'Already checked in today')

    # 兼容无 code 字段时的文案判定（包含 2026 新版 observation logged）
    success_keywords = (
        'checkin',
        'observation logged',
        'repeats',
        'already',
        'try tomorrow',
        'return tomorrow',
        'got ',
    )
    if any(k in msg_lower for k in success_keywords):
        return True, 'OK', msg

    return False, 'FAILED', f"未知响应 (code={code}, message={msg or 'empty'})"


# ================= 核心逻辑 =================

class GLaDOS:
    def __init__(self, cookie):
        self.cookie = cookie
        self.domain = DOMAINS[0]
        self.email = "?"
        self.left_days = "?"
        self.points = "?"
        self.points_change = "?"
        self.exchange_info = ""
        self.last_http_status = None
        self.last_error = ""

    def _ordered_domains(self):
        return [self.domain] + [d for d in DOMAINS if d != self.domain]

    def req(self, method, path, data=None):
        """带自动域名切换与 HTTP 状态记录的请求"""
        self.last_http_status = None
        self.last_error = ""

        for d in self._ordered_domains():
            try:
                url = f"{d}{path}"
                h = HEADERS.copy()
                h['Cookie'] = self.cookie
                h['Origin'] = d
                h['Referer'] = f"{d}/console/checkin"

                if method == 'GET':
                    resp = requests.get(url, headers=h, timeout=15)
                else:
                    resp = requests.post(url, headers=h, json=data, timeout=15)

                self.last_http_status = resp.status_code

                # 明确的认证失败，直接返回不再盲目切换域名
                if resp.status_code in (401, 403):
                    log(f"❌ {d}{path} 返回认证错误 HTTP {resp.status_code}")
                    try:
                        return resp.json()
                    except Exception:
                        return {'code': -2, 'message': f'HTTP {resp.status_code}'}

                if resp.status_code == 200:
                    self.domain = d
                    return resp.json()

                self.last_error = f"HTTP {resp.status_code}"
                log(f"⚠️ {d}{path} 返回状态码 {resp.status_code}")
            except Exception as e:
                self.last_error = str(e)
                log(f"⚠️ {d}{path} 请求失败: {e}")
                continue

        return None

    def get_status(self):
        """获取状态：验证 Cookie 有效性并获取邮箱与剩余天数"""
        res = self.req('GET', '/api/user/status')
        if is_auth_error(res, self.last_http_status):
            return False, 'COOKIE_EXPIRED', "状态接口返回未授权，Cookie 已过期或无效"

        if isinstance(res, dict) and isinstance(res.get('data'), dict):
            d = res['data']
            email = d.get('email')
            if email:
                self.email = str(email)
                self.left_days = str(d.get('leftDays', '?')).split('.')[0]
                return True, 'OK', 'ok'
            return False, 'COOKIE_EXPIRED', "状态接口未返回账号邮箱，Cookie 可能已失效"

        if res is None:
            return False, 'NETWORK_ERROR', f"获取账号状态失败 ({self.last_error or '网络错误'})"

        return False, 'FAILED', f"状态接口返回异常: {res.get('message', res)}"

    def get_points(self):
        """获取积分、变化历史、兑换计划"""
        res = self.req('GET', '/api/user/points')
        if isinstance(res, dict) and 'points' in res:
            self.points = str(res.get('points', '0')).split('.')[0]

            history = res.get('history', [])
            if history:
                last = history[0]
                change = str(last.get('change', '0')).split('.')[0]
                if not change.startswith('-'):
                    change = '+' + change
                self.points_change = change

            plans = res.get('plans', {})
            try:
                pts = int(self.points)
                exchange_lines = []
                for _, plan_data in plans.items():
                    need = plan_data['points']
                    days = plan_data['days']
                    if pts >= need:
                        exchange_lines.append(f"✅ {need}分→{days}天 (可兑换)")
                    else:
                        exchange_lines.append(f"❌ {need}分→{days}天 (差{need - pts}分)")
                self.exchange_info = "<br>".join(exchange_lines)
            except Exception:
                self.exchange_info = ""
            return True
        return False

    def checkin(self):
        """执行签到"""
        res = self.req('POST', '/api/user/checkin', {'token': 'glados.cloud'})
        return evaluate_checkin(res, self.last_http_status)


# ================= 推送与报告 =================

def pushplus(token, title, content):
    if not token:
        return
    try:
        url = "http://www.pushplus.plus/send"
        requests.get(
            url,
            params={'token': token, 'title': title, 'content': content, 'template': 'html'},
            timeout=5,
        )
        log("✅ PushPlus 推送成功")
    except Exception as e:
        log(f"❌ PushPlus 推送失败: {e}")


def write_github_summary(records, errors):
    """写入 GitHub Actions Job Summary，便于从告警邮件点进来一眼排查"""
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return

    lines = [
        "## GLaDOS 自动签到与监控报告",
        "",
        f"- **运行时间 (UTC)**: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`",
        f"- **总体状态**: {'❌ 检测到异常' if errors else '✅ 全部正常'}",
        "",
        "| # | 账号 | 积分 | 剩余天数 | 监控状态 | 详情 |",
        "|---|------|------|----------|----------|------|",
    ]
    for r in records:
        icon = "✅ 正常" if r['ok'] else f"❌ {r['status_type']}"
        lines.append(
            f"| {r['index']} | `{r['email']}` | {r['points']} ({r['points_change']}) | {r['left_days']} 天 | {icon} | {r['detail']} |"
        )

    if errors:
        lines.extend([
            "",
            "### 🚨 异常诊断与修复建议",
        ])
        for err in errors:
            lines.append(f"- {err}")
        lines.extend([
            "",
            "> 💡 若提示 **`COOKIE_EXPIRED`**，请登录 [glados.cloud](https://glados.cloud) 按 `F12 → Application → Cookies` 重新复制 `gld:sess` 和 `gld:sess.sig`，更新本仓库 `Settings → Secrets and variables → Actions → GLADOS_COOKIE`。",
        ])

    try:
        with open(summary_path, 'a', encoding='utf-8') as f:
            f.write("\n".join(lines) + "\n")
    except Exception as e:
        log(f"⚠️ 写入 GITHUB_STEP_SUMMARY 失败: {e}")


# ================= 主程序 =================

def main():
    log("🚀 2026 GLaDOS Checkin Starting (with Cookie & Task Monitor)...")
    cookies = get_cookies()
    if not cookies:
        log("❌ 监控告警: 未找到有效的 GLADOS_COOKIE，任务终止")
        sys.exit(1)

    results_html = []
    records = []
    errors = []
    success_cnt = 0

    for i, cookie in enumerate(cookies, 1):
        g = GLaDOS(cookie)

        # 1. 先检查账号状态（最直接检验 Cookie 是否仍有效）
        status_ok, status_type, status_msg = g.get_status()

        # 2. 执行签到
        checkin_ok, checkin_type, checkin_msg = g.checkin()

        # 3. 刷新最新状态与积分（签到成功后刷新天数和积分）
        if checkin_ok:
            refresh_ok, refresh_type, refresh_msg = g.get_status()
            if refresh_ok:
                status_ok, status_type, status_msg = refresh_ok, refresh_type, refresh_msg
            g.get_points()

        # 4. 综合判定：必须同时满足 Cookie 有效 且 签到成功
        if not status_ok:
            account_ok = False
            final_type = status_type
            final_detail = f"{status_msg} | 签到返回: {checkin_msg}"
        elif not checkin_ok:
            account_ok = False
            final_type = checkin_type
            final_detail = checkin_msg
        else:
            account_ok = True
            final_type = 'OK'
            final_detail = checkin_msg

        if account_ok:
            success_cnt += 1
            log(f"✅ 账号#{i} 正常 | 用户: {g.email} | 积分: {g.points} ({g.points_change}) | 剩余: {g.left_days} 天 | 结果: {final_detail}")
            # 剩余天数低预警（仅日志提示，不触发失败）
            try:
                if int(g.left_days) <= LOW_DAYS_WARN_THRESHOLD:
                    log(f"⚠️ 账号#{i} ({g.email}) 剩余天数仅剩 {g.left_days} 天，请注意及时用积分兑换或续期！")
            except ValueError:
                pass
        else:
            err_line = f"账号#{i} ({g.email}) [{final_type}]: {final_detail}"
            errors.append(err_line)
            log(f"❌ 账号#{i} 异常 | {err_line}")

        records.append({
            'index': i,
            'email': g.email,
            'points': g.points,
            'points_change': g.points_change,
            'left_days': g.left_days,
            'ok': account_ok,
            'status_type': final_type,
            'detail': final_detail,
        })

        # 组装可选的 PushPlus HTML 内容
        results_html.append(f"""
<div style="border:2px solid {'#27ae60' if account_ok else '#e74c3c'}; padding:15px; margin-bottom:15px; border-radius:10px; background:#fff;">
    <h3 style="margin:0 0 15px 0; color:#333; border-bottom:2px solid #333; padding-bottom:8px;">{'✅' if account_ok else '❌'} {g.email}</h3>
    <p style="margin:8px 0; color:#000; font-size:16px;"><b>当前积分:</b> <span style="color:#e74c3c; font-size:22px; font-weight:bold;">{g.points}</span> <span style="color:#27ae60; font-weight:bold;">({g.points_change})</span></p>
    <p style="margin:8px 0; color:#000; font-size:16px;"><b>剩余天数:</b> <span style="font-weight:bold;">{g.left_days} 天</span></p>
    <p style="margin:8px 0; color:#000; font-size:16px;"><b>监控结果:</b> [{final_type}] {final_detail}</p>
    <div style="margin-top:15px; padding:12px; background:#f0f0f0; border-radius:8px; border:1px solid #ccc;">
        <p style="margin:0 0 8px 0; color:#333; font-weight:bold; font-size:15px;">🎁 兑换选项:</p>
        <p style="margin:0; color:#000; font-size:14px; line-height:1.8;">{g.exchange_info}</p>
    </div>
</div>
""")

    # 写入 GitHub Actions Summary
    write_github_summary(records, errors)

    # 可选 PushPlus 推送
    ptoken = os.environ.get("PUSHPLUS_TOKEN")
    if ptoken:
        prefix = "GLaDOS签到异常告警" if errors else "GLaDOS签到"
        title = f"{prefix}: 成功{success_cnt}/{len(cookies)}"
        content = "".join(results_html) + f"<br><small>时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</small>"
        pushplus(ptoken, title, content)

    # 核心异常监控：任何账号 Cookie 失效或签到失败，强制以非零码退出触发 GitHub Actions 失败邮件告警
    if errors:
        log(f"🚨 监控告警触发：共 {len(errors)}/{len(cookies)} 个账号异常，退出码设为 1 以触发 GitHub Actions 告警通知！")
        sys.exit(1)

    log(f"🎉 监控检查通过：全部 {success_cnt}/{len(cookies)} 个账号 Cookie 与签到状态正常。")


if __name__ == '__main__':
    main()
