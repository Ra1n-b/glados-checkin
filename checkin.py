#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
2026 GLaDOS 自动签到 (Cookie & 任务监控 + QQ邮箱 SMTP 异常告警版)

功能：
- 全自动签到（兼容 2026 新版 glados.cloud API 与 gld:sess / koa:sess Cookie）
- 精准检测 Cookie 有效性、API 变更、网络异常与签到结果
- 异常时自动发送中文 HTML 告警邮件（支持 QQ 邮箱 SMTP，平时正常静默不打扰）
- 异常时以非零状态码退出（sys.exit(1)），触发 GitHub Actions 失败重试与红叉标记
- 输出 GitHub Actions Job Summary（含账号状态、积分、剩余天数、异常诊断）
"""

import json
import os
import smtplib
import sys
from datetime import datetime, timezone, timedelta
from email.header import Header
from email.mime.text import MIMEText
from email.utils import formataddr
import requests

# Fix Windows Unicode Output
if sys.platform.startswith('win'):
    sys.stdout.reconfigure(encoding='utf-8')

# ================= 配置 =================

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

LOW_DAYS_WARN_THRESHOLD = 7
BJ_TZ = timezone(timedelta(hours=8))

# ================= 工具函数 =================

def now_bj_str():
    return datetime.now(BJ_TZ).strftime("%Y-%m-%d %H:%M:%S (北京时间)")


def log(msg):
    ts = datetime.now(BJ_TZ).strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {msg}")


def extract_cookie(raw: str):
    """提取 Cookie，兼容 gld:sess / koa:sess / Cookie-Editor / JSON / JWT 格式"""
    if not raw:
        return None
    raw = raw.strip()

    if 'gld:sess=' in raw or 'koa:sess=' in raw or 'koa:sess.sig=' in raw:
        return raw

    if raw.startswith('{'):
        try:
            token = json.loads(raw).get('token')
            if token:
                return 'koa.sess=' + token
        except Exception:
            pass

    if raw.count('.') == 2 and '=' not in raw and len(raw) > 50:
        return 'koa:sess=' + raw

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
    status_type: 'OK' | 'COOKIE_EXPIRED' | 'API_CHANGED' | 'NETWORK_ERROR' | 'FAILED'
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

    if 'please checkin via' in msg_lower:
        return False, 'API_CHANGED', f"GLaDOS 签到接口/Token 已变更: {msg}"

    error_keywords = ('fail', 'error', 'invalid', 'denied', 'forbidden')
    if any(k in msg_lower for k in error_keywords):
        return False, 'FAILED', msg or f"签到失败 (code={code})"

    if code in (0, 1):
        return True, 'OK', msg or ('Checkin succeeded' if code == 0 else 'Already checked in today')

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


# ================= 邮件与推送 =================

def build_email_html(records, errors, is_test=False):
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    secrets_url = f"https://github.com/{repo}/settings/secrets/actions" if repo else "https://github.com"
    actions_url = f"https://github.com/{repo}/actions" if repo else "https://github.com"

    banner_bg = "#e74c3c" if errors else "#27ae60"
    banner_title = (
        "🚨 GLaDOS 自动签到监控告警"
        if errors
        else ("✅ GLaDOS 邮箱告警通道测试成功" if is_test else "✅ GLaDOS 自动签到报告")
    )

    rows_html = []
    for r in records:
        status_badge = (
            '<span style="color:#27ae60;font-weight:bold;">✅ 正常</span>'
            if r['ok']
            else f'<span style="color:#e74c3c;font-weight:bold;">❌ {r["status_type"]}</span>'
        )
        rows_html.append(
            f"""
            <tr>
                <td style="padding:8px;border:1px solid #ddd;">{r['email']}</td>
                <td style="padding:8px;border:1px solid #ddd;">{r['points']} ({r['points_change']})</td>
                <td style="padding:8px;border:1px solid #ddd;">{r['left_days']} 天</td>
                <td style="padding:8px;border:1px solid #ddd;">{status_badge}</td>
                <td style="padding:8px;border:1px solid #ddd;">{r['detail']}</td>
            </tr>
            """
        )

    errors_block = ""
    if errors:
        err_items = "".join(f"<li style='margin:6px 0;'>{e}</li>" for e in errors)
        errors_block = f"""
        <div style="margin-top:16px;padding:12px 16px;background:#fff5f5;border-left:4px solid #e74c3c;border-radius:4px;">
            <p style="margin:0 0 8px 0;font-weight:bold;color:#c0392b;">异常详情：</p>
            <ul style="margin:0;padding-left:20px;color:#333;">{err_items}</ul>
            <p style="margin:12px 0 0 0;font-size:13px;color:#555;">
                💡 若提示 <b>COOKIE_EXPIRED</b>，请重新登录 <a href="https://glados.cloud">glados.cloud</a> 获取 <code>gld:sess</code> 与 <code>gld:sess.sig</code>，
                并前往 <a href="{secrets_url}">GitHub Secrets 页面</a> 更新 <code>GLADOS_COOKIE</code>。
            </p>
        </div>
        """

    return f"""
    <div style="font-family:Arial,sans-serif;max-width:680px;margin:0 auto;border:1px solid #e0e0e0;border-radius:8px;overflow:hidden;">
        <div style="background:{banner_bg};color:#fff;padding:16px 20px;">
            <h2 style="margin:0;font-size:18px;">{banner_title}</h2>
            <p style="margin:6px 0 0 0;font-size:13px;opacity:0.9;">检查时间：{now_bj_str()}</p>
        </div>
        <div style="padding:18px 20px;">
            <table style="width:100%;border-collapse:collapse;font-size:14px;">
                <thead>
                    <tr style="background:#f7f7f7;">
                        <th style="padding:8px;border:1px solid #ddd;text-align:left;">账号</th>
                        <th style="padding:8px;border:1px solid #ddd;text-align:left;">积分</th>
                        <th style="padding:8px;border:1px solid #ddd;text-align:left;">剩余天数</th>
                        <th style="padding:8px;border:1px solid #ddd;text-align:left;">状态</th>
                        <th style="padding:8px;border:1px solid #ddd;text-align:left;">详情</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(rows_html) if rows_html else '<tr><td colspan="5" style="padding:8px;border:1px solid #ddd;">无账号记录</td></tr>'}
                </tbody>
            </table>
            {errors_block}
            <p style="margin:16px 0 0 0;font-size:12px;color:#888;">
                查看完整运行日志：<a href="{actions_url}">{actions_url}</a>
            </p>
        </div>
    </div>
    """


def send_smtp_email(subject, html_content):
    """通过 SMTP（默认 QQ 邮箱 SSL 465）发送告警或测试邮件"""
    smtp_user = os.environ.get("SMTP_USER", "").strip()
    smtp_pass = os.environ.get("SMTP_PASS", "").strip()
    to_email = os.environ.get("ALERT_EMAIL", "").strip() or smtp_user
    smtp_host = os.environ.get("SMTP_HOST", "").strip() or "smtp.qq.com"
    smtp_port = int(os.environ.get("SMTP_PORT", "465").strip() or "465")

    if not smtp_user or not smtp_pass:
        log("ℹ️ 未配置 SMTP_USER / SMTP_PASS，跳过邮件告警发送")
        return False

    try:
        msg = MIMEText(html_content, 'html', 'utf-8')
        msg['From'] = formataddr((str(Header("GLaDOS 签到监控", 'utf-8')), smtp_user))
        msg['To'] = to_email
        msg['Subject'] = Header(subject, 'utf-8')

        with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=15) as server:
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, [to_email], msg.as_string())

        log(f"✅ 邮件通知已发送至 {to_email}")
        return True
    except Exception as e:
        log(f"❌ 邮件发送失败: {e}")
        return False


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
    """写入 GitHub Actions Job Summary"""
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return

    lines = [
        "## GLaDOS 自动签到与监控报告",
        "",
        f"- **检查时间**: `{now_bj_str()}`",
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
        lines.extend(["", "### 🚨 异常诊断与修复建议"])
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
    log("🚀 2026 GLaDOS Checkin Starting (with Cookie Monitor & SMTP Alert)...")
    skip_email_on_fail = os.environ.get("SKIP_EMAIL_ON_FAIL", "").lower() == "true"
    force_alert_test = os.environ.get("FORCE_ALERT_TEST", "").lower() == "true"

    cookies = get_cookies()
    if not cookies:
        err = "未配置有效的 GLADOS_COOKIE 环境变量"
        log(f"❌ 监控告警: {err}")
        write_github_summary([], [err])
        if not skip_email_on_fail:
            send_smtp_email(
                "🚨 [GLaDOS 监控告警] 未配置 GLADOS_COOKIE",
                build_email_html([], [err]),
            )
        sys.exit(1)

    results_html = []
    records = []
    errors = []
    success_cnt = 0

    for i, cookie in enumerate(cookies, 1):
        g = GLaDOS(cookie)

        # 1. 先检查账号状态（直接验证 Cookie 有效性）
        status_ok, status_type, status_msg = g.get_status()

        # 2. 执行签到
        checkin_ok, checkin_type, checkin_msg = g.checkin()

        # 3. 签到成功后刷新最新状态与积分
        if checkin_ok:
            refresh_ok, refresh_type, refresh_msg = g.get_status()
            if refresh_ok:
                status_ok, status_type, status_msg = refresh_ok, refresh_type, refresh_msg
            g.get_points()

        # 4. 综合判定
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
            try:
                if int(g.left_days) <= LOW_DAYS_WARN_THRESHOLD:
                    log(f"⚠️ 账号#{i} ({g.email}) 剩余天数仅剩 {g.left_days} 天，请注意续期或兑换！")
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

        results_html.append(f"""
<div style="border:2px solid {'#27ae60' if account_ok else '#e74c3c'}; padding:15px; margin-bottom:15px; border-radius:10px; background:#fff;">
    <h3 style="margin:0 0 15px 0; color:#333; border-bottom:2px solid #333; padding-bottom:8px;">{'✅' if account_ok else '❌'} {g.email}</h3>
    <p style="margin:8px 0; color:#000; font-size:16px;"><b>当前积分:</b> <span style="color:#e74c3c; font-size:22px; font-weight:bold;">{g.points}</span> <span style="color:#27ae60; font-weight:bold;">({g.points_change})</span></p>
    <p style="margin:8px 0; color:#000; font-size:16px;"><b>剩余天数:</b> <span style="font-weight:bold;">{g.left_days} 天</span></p>
    <p style="margin:8px 0; color:#000; font-size:16px;"><b>监控结果:</b> [{final_type}] {final_detail}</p>
</div>
""")

    write_github_summary(records, errors)

    # 可选 PushPlus 推送
    ptoken = os.environ.get("PUSHPLUS_TOKEN")
    if ptoken:
        prefix = "GLaDOS签到异常告警" if errors else "GLaDOS签到"
        title = f"{prefix}: 成功{success_cnt}/{len(cookies)}"
        pushplus(ptoken, title, "".join(results_html) + f"<br><small>时间: {now_bj_str()}</small>")

    # 邮件告警：异常时发送（若为首轮失败等待重试则暂缓发送，避免偶发抖动误报）
    if errors:
        if skip_email_on_fail:
            log("⏳ 首轮检测到异常，暂缓发邮件，等待 60s 后重试确认...")
        else:
            has_cookie_err = any(r['status_type'] == 'COOKIE_EXPIRED' for r in records)
            subject = (
                "🚨 [GLaDOS 监控告警] Cookie 已过期，请尽快更新"
                if has_cookie_err
                else f"🚨 [GLaDOS 监控告警] 签到任务异常 ({len(errors)}/{len(cookies)} 失败)"
            )
            send_smtp_email(subject, build_email_html(records, errors, is_test=False))
        log(f"🚨 监控告警触发：共 {len(errors)}/{len(cookies)} 个账号异常，退出码设为 1。")
        sys.exit(1)

    # 手动测试邮件通道（即使正常也发一封测试邮件）
    if force_alert_test:
        log("📧 检测到测试模式 (FORCE_ALERT_TEST=true)，正在发送测试邮件验证 QQ 邮箱告警通道...")
        ok = send_smtp_email(
            "✅ [GLaDOS 监控测试] QQ 邮箱告警通道配置成功",
            build_email_html(records, [], is_test=True),
        )
        if not ok:
            log("❌ 测试邮件发送失败，请检查 SMTP_USER / SMTP_PASS（16位 QQ 邮箱授权码）是否正确！")
            sys.exit(1)

    log(f"🎉 监控检查通过：全部 {success_cnt}/{len(cookies)} 个账号 Cookie 与签到状态正常（静默模式，无异常不发邮件）。")


if __name__ == '__main__':
    main()
