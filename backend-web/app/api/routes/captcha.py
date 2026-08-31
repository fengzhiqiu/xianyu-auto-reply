"""
验证码相关路由

包含图形验证码和邮箱验证码功能
"""
from __future__ import annotations

import asyncio
import json
import math
import random
import re
import string
import time
from typing import Optional

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from loguru import logger

from app.api import deps
from app.services.remote_captcha_admission_service import (
    DEFAULT_REMOTE_COOLDOWN_SECONDS,
    DEFAULT_REMOTE_PROCESSING_MAX,
    REMOTE_COOLDOWN_SECONDS_KEY,
    REMOTE_PROCESSING_MAX_KEY,
    RemoteCaptchaAdmissionService,
    RemoteCaptchaAdmissionRedisUnavailable,
    sanitize_nonnegative_int,
)
from app.services.risk_control_log_service import RiskControlLogService
from app.services.system_setting_service import SystemSettingService
from app.services.websocket_client import websocket_client
from common.db.session import async_session_maker
from common.models.system_setting import SystemSetting
from common.models.user import User
from common.schemas.common import ApiResponse

router = APIRouter(prefix="/captcha", tags=["验证码"])


# ==================== 请求/响应模型 ====================

class CaptchaRequest(BaseModel):
    """图形验证码请求"""
    session_id: str


class VerifyCaptchaRequest(BaseModel):
    """验证图形验证码请求"""
    session_id: str
    captcha_code: str


class SendCodeRequest(BaseModel):
    """发送邮箱验证码请求"""
    email: EmailStr
    session_id: Optional[str] = None
    type: str = "register"  # register, login 或 reset_password
    # 极验滑动验证参数（仅忘记密码 reset_password 场景使用，参照登录逻辑）
    geetest_challenge: Optional[str] = None
    geetest_validate: Optional[str] = None
    geetest_seccode: Optional[str] = None


class SliderSolveRequest(BaseModel):
    """过滑块请求（模式B，外部使用）"""
    secret_key: str                      # 用户个人设置中的秘钥（用于身份校验，查到用户名）
    account_id: str = ""                 # 外部账号标识（仅用于日志/浏览器实例隔离，本系统不查库）
    url: str                             # punish 验证链接（punish?x5secdata=...）
    browser_timeout: int = 40            # 单次浏览器超时（秒），范围 20~120
    cookies: str = ""                    # 可选：账号 Cookie（调用方开启"传递Cookie"开关时传入），
                                         # 用于链接过期时凭 Cookie 重取新链接继续处理
    device_id: str = ""                  # 可选：设备 ID，配合 cookies 重新请求 token 接口使用


class TestRemoteSolveRequest(BaseModel):
    """测试远程过滑块服务连通性请求"""
    url: str                             # 远程过滑块服务URL
    secret_key: str = ""                 # 秘钥（用于校验远程是否接受该秘钥）


class RemoteConfigUpdate(BaseModel):
    """远程过滑块全局配置（仅管理员）"""
    url: str = ""
    secret_key: str = ""
    pass_cookies: bool = False   # 是否在调用远程接口时传递账号 Cookie（默认关闭）
    block_remote_calls: bool = True  # 是否禁止外部系统调用本机过滑块接口（默认开启）
    # real_mouse 过滑块本地/远程排队权重（>=0），多来源同时排队时按比例放行，默认 1:1
    local_weight: float = 1
    remote_weight: float = 1
    remote_processing_max: Optional[int] = None
    remote_cooldown_seconds: Optional[int] = None


# 远程过滑块全局配置存储 key（system_settings，全局唯一，仅管理员可读写）
REMOTE_CONFIG_URL_KEY = "captcha.remote_service_url"
REMOTE_CONFIG_SECRET_KEY = "captcha.remote_secret_key"
REMOTE_CONFIG_PASS_COOKIES_KEY = "captcha.remote_pass_cookies"
REMOTE_CONFIG_BLOCK_REMOTE_CALLS_KEY = "captcha.block_remote_calls"
# real_mouse 排队权重（与 common/services/captcha/weighted_scheduler.py 的键保持一致）
REMOTE_CONFIG_WEIGHT_LOCAL_KEY = "captcha.real_mouse_weight_local"
REMOTE_CONFIG_WEIGHT_REMOTE_KEY = "captcha.real_mouse_weight_remote"

# Token获取方式专用域名：这些是取Token的远程接口地址，不属于过滑块远程服务，
# 误填到风控日志的远程服务URL会导致过滑块一直失败，因此保存时直接拦截。
TOKEN_API_ONLY_DOMAINS = ("api.xianyusite.shop", "api.zhinianblog.cn")


def _check_token_api_domain(url: str) -> Optional[ApiResponse]:
    """
    校验过滑块远程服务URL是否误填了「Token获取方式」的接口域名。

    保存与测试两处入口共用，命中则直接返回失败响应，避免各处重复写文案。

    Args:
        url: 用户填写的远程过滑块服务URL
    Returns:
        命中时返回失败的 ApiResponse；未命中返回 None
    """
    lowered = (url or "").strip().lower()
    for domain in TOKEN_API_ONLY_DOMAINS:
        if domain in lowered:
            return ApiResponse(
                success=False,
                message=f"该URL（{domain}）不是在此处填写，需要在「系统设置-Token获取方式」中填写",
            )
    return None


def _sanitize_weight(value, default: float = 1.0) -> float:
    """把权重值规整为非负浮点数，非法则回退默认（1）。"""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return default
    return v if math.isfinite(v) and v >= 0 else default


async def _is_remote_slider_blocked(db: AsyncSession) -> bool:
    """读取是否禁止外部远程调用本机过滑块接口。"""
    result = await db.execute(
        select(SystemSetting.value).where(SystemSetting.key == REMOTE_CONFIG_BLOCK_REMOTE_CALLS_KEY)
    )
    value = (result.scalar_one_or_none() or "true").strip().lower()
    return value == "true"


# ==================== 工具函数 ====================

def generate_captcha_text(length: int = 4) -> str:
    """生成随机验证码文本"""
    # 排除容易混淆的字符: 0, O, 1, I, l
    chars = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
    return "".join(random.choices(chars, k=length))


def _load_captcha_font(size: int = 28):
    """
    按候选路径加载验证码字体。

    Why: Linux 容器（python:3.11-slim）默认没有 arial.ttf，原先直接
    truetype("arial.ttf") 抛异常后 fallback 到 load_default() 的位图字体
    极小（~10px），用户看到的验证码图片几乎是空白。
    这里按优先级尝试各平台常见 TTF 路径，全部失败再退回默认字体。
    """
    from PIL import ImageFont
    import os

    # 全部使用绝对路径，避免 truetype 解析相对路径时抛异常拖慢生成
    candidates = [
        # Linux 容器（apt 安装 fonts-dejavu-core / fonts-liberation 后存在）
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        # Windows 本地开发
        "C:/Windows/Fonts/arial.ttf",
        "C:/Windows/Fonts/arialbd.ttf",
        # macOS
        "/System/Library/Fonts/Helvetica.ttc",
        "/Library/Fonts/Arial.ttf",
    ]
    for path in candidates:
        if not os.path.exists(path):
            continue
        try:
            return ImageFont.truetype(path, size)
        except Exception:
            continue

    # 全部 TTF 都不可用时的兜底：Pillow 10+ 支持 load_default(size)
    try:
        return ImageFont.load_default(size=size)
    except TypeError:
        # 老版本 Pillow 不支持 size 参数，只能回退到默认小字体
        return ImageFont.load_default()


def generate_captcha_image(text: str) -> str:
    """
    生成图形验证码图片
    
    返回base64编码的图片
    """
    try:
        from PIL import Image, ImageDraw, ImageFont
        import io
        import base64
        
        # 图片尺寸
        width, height = 120, 40
        
        # 创建图片
        image = Image.new("RGB", (width, height), color=(255, 255, 255))
        draw = ImageDraw.Draw(image)
        
        # 添加干扰线
        for _ in range(5):
            x1 = random.randint(0, width)
            y1 = random.randint(0, height)
            x2 = random.randint(0, width)
            y2 = random.randint(0, height)
            draw.line(
                [(x1, y1), (x2, y2)], 
                fill=(random.randint(0, 200), random.randint(0, 200), random.randint(0, 200))
            )
        
        # 添加干扰点
        for _ in range(50):
            x = random.randint(0, width)
            y = random.randint(0, height)
            draw.point(
                (x, y), 
                fill=(random.randint(0, 200), random.randint(0, 200), random.randint(0, 200))
            )
        
        # 绘制文字
        font = _load_captcha_font(28)
        
        # 计算文字位置
        for i, char in enumerate(text):
            x = 10 + i * 25 + random.randint(-3, 3)
            y = random.randint(2, 10)
            color = (random.randint(0, 150), random.randint(0, 150), random.randint(0, 150))
            draw.text((x, y), char, font=font, fill=color)
        
        # 转换为base64
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        img_str = base64.b64encode(buffer.getvalue()).decode()
        
        return f"data:image/png;base64,{img_str}"
        
    except Exception as e:
        logger.error(f"生成验证码图片失败: {e}")
        return ""


def generate_verification_code(length: int = 6) -> str:
    """生成数字验证码"""
    return "".join(random.choices(string.digits, k=length))


# ==================== 内存存储（简化实现，生产环境建议用Redis） ====================

# 图形验证码存储: {session_id: {"code": str, "expires_at": float}}
captcha_store: dict = {}

# 邮箱验证码存储: {email: {"code": str, "type": str, "expires_at": float, "fail_count": int}}
email_code_store: dict = {}

# 单个邮箱验证码最大允许尝试次数，超过即作废（防暴力枚举）
MAX_EMAIL_CODE_ATTEMPTS = 5


def cleanup_expired_captcha():
    """清理过期的验证码"""
    current_time = time.time()
    expired_keys = [k for k, v in captcha_store.items() if v["expires_at"] < current_time]
    for k in expired_keys:
        del captcha_store[k]


def cleanup_expired_email_codes():
    """清理过期的邮箱验证码"""
    current_time = time.time()
    expired_keys = [k for k, v in email_code_store.items() if v["expires_at"] < current_time]
    for k in expired_keys:
        del email_code_store[k]


# ==================== 路由 ====================

@router.post("/generate")
async def generate_captcha(request: CaptchaRequest) -> ApiResponse:
    """生成图形验证码"""
    try:
        cleanup_expired_captcha()
        
        # 生成验证码
        captcha_text = generate_captcha_text()
        captcha_image = generate_captcha_image(captcha_text)
        
        if not captcha_image:
            return ApiResponse(
                success=False,
                message="图形验证码生成失败"
            )
        
        # 保存验证码（5分钟有效）
        captcha_store[request.session_id] = {
            "code": captcha_text.upper(),
            "expires_at": time.time() + 300
        }
        
        logger.info(f"生成图形验证码: session_id={request.session_id}")
        
        return ApiResponse(
            success=True,
            message="图形验证码生成成功",
            data={
                "captcha_image": captcha_image,
                "session_id": request.session_id
            }
        )
        
    except Exception as e:
        logger.error(f"生成图形验证码失败: {e}")
        return ApiResponse(
            success=False,
            message="图形验证码生成失败"
        )


@router.post("/verify")
async def verify_captcha(request: VerifyCaptchaRequest) -> ApiResponse:
    """验证图形验证码"""
    try:
        cleanup_expired_captcha()
        
        stored = captcha_store.get(request.session_id)
        
        if not stored:
            return ApiResponse(
                success=False,
                message="验证码不存在或已过期"
            )
        
        if stored["expires_at"] < time.time():
            del captcha_store[request.session_id]
            return ApiResponse(
                success=False,
                message="验证码已过期"
            )
        
        if stored["code"] != request.captcha_code.upper():
            return ApiResponse(
                success=False,
                message="验证码错误"
            )
        
        # 验证成功后删除
        del captcha_store[request.session_id]
        
        logger.info(f"图形验证码验证成功: session_id={request.session_id}")
        
        return ApiResponse(
            success=True,
            message="验证码验证成功"
        )
        
    except Exception as e:
        logger.error(f"验证图形验证码失败: {e}")
        return ApiResponse(
            success=False,
            message="验证码验证失败"
        )


@router.post("/send-email-code")
async def send_email_verification_code(
    request: SendCodeRequest,
    db: AsyncSession = Depends(deps.get_db_session),
) -> ApiResponse:
    """发送邮箱验证码"""
    try:
        cleanup_expired_email_codes()

        from app.services.user_service import UserService
        user_service = UserService(db)

        # 忘记密码场景：参照登录逻辑，开启滑动验证时必须先通过极验二次验证
        if request.type == "reset_password":
            setting_service = SystemSettingService(db)
            all_settings = await setting_service.list_settings()
            captcha_enabled_str = all_settings.get("login_captcha_enabled")
            captcha_enabled = captcha_enabled_str in (None, "true", "1")  # 默认开启
            if captcha_enabled:
                from app.api.routes.geetest import check_geetest_verified

                if not request.geetest_challenge:
                    return ApiResponse(success=False, message="请完成滑动验证")

                geetest_ok, geetest_msg = check_geetest_verified(request.geetest_challenge)
                if not geetest_ok:
                    return ApiResponse(success=False, message=geetest_msg)

        # 根据类型检查邮箱
        if request.type == "register":
            existing_user = await user_service.get_by_email(request.email)
            if existing_user:
                return ApiResponse(
                    success=False,
                    message="该邮箱已被注册"
                )
        elif request.type == "login":
            existing_user = await user_service.get_by_email(request.email)
            if not existing_user:
                return ApiResponse(
                    success=False,
                    message="该邮箱未注册"
                )
        elif request.type == "reset_password":
            existing_user = await user_service.get_by_email(request.email)
            if not existing_user:
                return ApiResponse(
                    success=False,
                    message="该邮箱未注册"
                )
        
        # 检查发送频率（1分钟内只能发送一次）
        stored = email_code_store.get(request.email)
        if stored and stored["expires_at"] - 240 > time.time():
            return ApiResponse(
                success=False,
                message="验证码发送过于频繁，请稍后再试"
            )
        
        # 生成验证码
        code = generate_verification_code()
        
        # 保存验证码（5分钟有效）
        email_code_store[request.email] = {
            "code": code,
            "type": request.type,
            "expires_at": time.time() + 300
        }
        
        # 发送邮件
        from app.services.email_service import send_verification_code_email
        success, message = await send_verification_code_email(request.email, code, request.type)
        
        if not success:
            # 发送失败，删除验证码
            del email_code_store[request.email]
            return ApiResponse(
                success=False,
                message=message
            )
        
        logger.info(f"发送邮箱验证码成功: email={request.email}, type={request.type}")
        
        return ApiResponse(
            success=True,
            message="验证码已发送到您的邮箱，请查收"
        )
        
    except Exception as e:
        logger.error(f"发送邮箱验证码失败: {e}")
        return ApiResponse(
            success=False,
            message="验证码发送失败，请稍后重试"
        )


@router.post("/verify-email-code")
async def verify_email_code(
    email: str,
    code: str,
    code_type: str = "register",
) -> ApiResponse:
    """验证邮箱验证码"""
    cleanup_expired_email_codes()
    
    stored = email_code_store.get(email)
    
    if not stored:
        return ApiResponse(success=False, message="验证码不存在或已过期")
    
    if stored["expires_at"] < time.time():
        del email_code_store[email]
        return ApiResponse(success=False, message="验证码已过期")
    
    if stored["code"] != code:
        return ApiResponse(success=False, message="验证码错误")
    
    if stored["type"] != code_type:
        return ApiResponse(success=False, message="验证码类型不匹配")
    
    # 验证成功后删除
    del email_code_store[email]
    
    return ApiResponse(success=True, message="验证码验证成功")


def check_email_code(email: str, code: str, code_type: str = "login") -> tuple[bool, str]:
    """
    验证邮箱验证码（供其他模块调用）

    返回: (是否成功, 消息)

    安全说明：单个验证码最多允许尝试 MAX_EMAIL_CODE_ATTEMPTS 次，
    超过后立即作废，防止 6 位数字验证码被暴力枚举。
    """
    cleanup_expired_email_codes()

    stored = email_code_store.get(email)

    if not stored:
        return False, "验证码不存在或已过期"

    if stored["expires_at"] < time.time():
        del email_code_store[email]
        return False, "验证码已过期"

    if stored["type"] != code_type:
        return False, "验证码类型不匹配"

    if stored["code"] != code:
        # 记录失败次数，超过上限直接作废，避免暴力枚举
        stored["fail_count"] = stored.get("fail_count", 0) + 1
        if stored["fail_count"] >= MAX_EMAIL_CODE_ATTEMPTS:
            del email_code_store[email]
            return False, "验证码错误次数过多，请重新获取验证码"
        remaining = MAX_EMAIL_CODE_ATTEMPTS - stored["fail_count"]
        return False, f"验证码错误，还可尝试 {remaining} 次"

    # 验证成功后删除
    del email_code_store[email]

    return True, "验证码验证成功"


# ==================== 过滑块（外部接口，模式B） ====================

@router.post("/slider-solve")
async def slider_solve(
    request: SliderSolveRequest,
    db: AsyncSession = Depends(deps.get_db_session),
) -> ApiResponse:
    """过滑块（供外部系统调用）。

    模式B：仅凭传入的 punish 链接求解，本系统不查账号库、不回填 cookies。
    - 鉴权：必须传入有效的用户秘钥（个人设置中的秘钥），校验存在即放行，并据此记录调用用户。
    - 成功：data = { engine, cookies: { x5sec, ... } }
    - 失败：success=false
    """
    try:
        remote_calls_blocked = await _is_remote_slider_blocked(db)
    except Exception as exc:
        logger.error(f"检查远程过滑块禁用配置失败: {exc}")
        return ApiResponse(success=False, message="检查远程过滑块调用配置失败，请稍后重试")
    if remote_calls_blocked:
        return ApiResponse(success=False, message="系统已禁止远程过滑块调用")

    secret_key = (request.secret_key or "").strip()
    if not secret_key:
        return ApiResponse(success=False, message="缺少秘钥")

    # 校验秘钥是否存在（个人设置中的用户秘钥），并查出用户名
    try:
        result = await db.execute(select(User).where(User.secret_key == secret_key))
    except Exception as exc:
        logger.error(f"校验远程过滑块调用秘钥失败: {exc}")
        return ApiResponse(success=False, message="校验远程过滑块调用秘钥失败，请稍后重试")
    user = result.scalar_one_or_none()
    if not user:
        return ApiResponse(success=False, message="无效的秘钥")

    url = (request.url or "").strip()
    if not url:
        return ApiResponse(success=False, message="punish 链接不能为空")

    raw_account_id = (request.account_id or "external").strip()
    safe_account_id = re.sub(r"[^A-Za-z0-9_-]", "", raw_account_id)[:64] or "external"
    timeout = max(20, min(int(request.browser_timeout or 40), 120))
    precreated_log_id = None
    try:
        async with async_session_maker() as admission_db:
            admission_service = RemoteCaptchaAdmissionService(admission_db)
            try:
                (
                    admission_allowed,
                    rejection_message,
                    precreated_log_id,
                ) = await admission_service.check_admission_with_redis_log(
                    account_identifier=safe_account_id,
                    url=url,
                    call_user=user.username,
                )
            except RemoteCaptchaAdmissionRedisUnavailable as exc:
                logger.warning(
                    f"Redis远程过滑块准入不可用，降级为原有数据库计数逻辑: {exc}"
                )
                admission_allowed, rejection_message = await (
                    RemoteCaptchaAdmissionService(db).check_admission()
                )
    except Exception as exc:
        logger.error(f"检查远程过滑块调用容量失败: {exc}")
        return ApiResponse(success=False, message="检查远程过滑块调用容量失败，请稍后重试")
    if not admission_allowed:
        return ApiResponse(success=False, message=rejection_message or "远程过滑块调用已拒绝")

    result_data = await websocket_client.solve_captcha(
        account_id=safe_account_id,
        url=url,
        browser_timeout=timeout,
        call_type="remote",
        call_user=user.username,
        cookies=(request.cookies or "").strip(),
        device_id=(request.device_id or "").strip(),
        extended_queue_timeout=True,
        precreated_log_id=precreated_log_id,
    )

    request_not_sent = bool(
        isinstance(result_data, dict) and result_data.pop("_request_not_sent", False)
    )
    request_status_unknown = bool(
        isinstance(result_data, dict)
        and result_data.pop("_request_status_unknown", False)
    )
    acknowledged_log_id = (
        result_data.pop("_risk_log_id", None) if isinstance(result_data, dict) else None
    )
    log_not_acknowledged = (
        precreated_log_id is not None
        and not request_not_sent
        and not request_status_unknown
        and acknowledged_log_id != precreated_log_id
    )
    if precreated_log_id and (request_not_sent or log_not_acknowledged):
        if request_not_sent:
            cleanup_message = result_data.get("message") or "websocket 服务连接失败"
        else:
            cleanup_message = "websocket 服务未确认预建风控日志，可能仍在运行旧版本"
        try:
            async with async_session_maker() as log_db:
                await RiskControlLogService(log_db).mark_remote_slider_log_unclaimed(
                    log_id=precreated_log_id,
                    error_message=cleanup_message,
                )
        except Exception as exc:
            logger.error(f"释放未被 websocket 接管的远程过滑块风控日志失败: {exc}")

    if isinstance(result_data, dict) and result_data.get("success"):
        return ApiResponse(success=True, message="过滑块成功", data=result_data.get("data"))
    message = (result_data or {}).get("message") if isinstance(result_data, dict) else None
    data = (result_data or {}).get("data") if isinstance(result_data, dict) else None
    return ApiResponse(success=False, message=message or "过滑块失败", data=data)


@router.post("/slider-solve/test")
async def test_remote_slider_solve(
    request: TestRemoteSolveRequest,
    current_user: User = Depends(deps.get_current_admin_user),  # 仅管理员可发起（也避免被滥用做 SSRF）
) -> ApiResponse:
    """测试远程过滑块服务连通性与秘钥有效性（服务端代理请求，规避浏览器跨域）。

    以一个“空 punish 链接”探测：远程会先校验秘钥，再校验链接，据此判断：
    - 秘钥无效 → 连接成功但秘钥无效
    - 提示缺少链接/其它正常业务响应 → 连接成功且秘钥有效
    - 网络异常 → 无法连接
    """
    import aiohttp

    url = (request.url or "").strip()
    if not url:
        return ApiResponse(success=False, message="请先填写远程服务URL")
    if not url.lower().startswith(("http://", "https://")):
        return ApiResponse(success=False, message="远程服务URL 必须以 http:// 或 https:// 开头")
    # 误填Token获取接口域名时直接拦截，不向远程发起请求
    domain_error = _check_token_api_domain(url)
    if domain_error:
        return domain_error

    payload = {
        "secret_key": (request.secret_key or "").strip(),
        "account_id": "connectivity-test",
        "url": "",  # 故意留空：只测连通+秘钥，不真正过滑块
    }
    logger.info(f"[过滑块测试] 请求远程服务 url={url} payload={payload}")
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            async with session.post(url, json=payload) as resp:
                # 打印远程服务原始返回（状态码 + 文本）
                raw_text = await resp.text()
                logger.info(
                    f"[过滑块测试] 远程响应 status={resp.status} body={raw_text}"
                )
                try:
                    body = await resp.json(content_type=None)
                except Exception:
                    body = {}

                # 非 200 一律视为连接/路径异常（如 404 表示远程没有该接口、502 表示远程服务异常）
                if resp.status != 200:
                    detail = ""
                    if isinstance(body, dict):
                        detail = str(body.get("detail") or body.get("message") or "").strip()
                    detail = detail or (raw_text or "").strip()
                    result = ApiResponse(
                        success=False,
                        message=f"远程服务返回异常（HTTP {resp.status}）：{detail or '无响应内容'}，请检查远程服务URL是否正确",
                    )
                    logger.info(f"[过滑块测试] 接口返回 {result.model_dump()}")
                    return result

                msg = ((body or {}).get("message") if isinstance(body, dict) else "") or ""
                msg = msg.strip()
                if "秘钥" in msg and ("无效" in msg or "缺少" in msg):
                    result = ApiResponse(success=False, message=f"连接成功，但秘钥无效（远程：{msg}）")
                elif "禁止远程" in msg:
                    result = ApiResponse(success=False, message=f"连接成功，但远程服务已拒绝调用（远程：{msg}）")
                else:
                    result = ApiResponse(success=True, message=f"连接成功（远程返回：{msg or '正常'}）")
                logger.info(f"[过滑块测试] 接口返回 {result.model_dump()}")
                return result
    except Exception as e:
        result = ApiResponse(success=False, message=f"无法连接到远程服务：{str(e)}")
        logger.info(f"[过滑块测试] 接口返回 {result.model_dump()}")
        return result


@router.get("/remote-config")
async def get_remote_config(
    current_user: User = Depends(deps.get_current_admin_user),  # 仅管理员可读
    db: AsyncSession = Depends(deps.get_db_session),
) -> ApiResponse:
    """读取远程过滑块全局配置（仅管理员）。"""
    try:
        rows = (await db.execute(
            select(SystemSetting).where(
                SystemSetting.key.in_([
                    REMOTE_CONFIG_URL_KEY,
                    REMOTE_CONFIG_SECRET_KEY,
                    REMOTE_CONFIG_PASS_COOKIES_KEY,
                    REMOTE_CONFIG_BLOCK_REMOTE_CALLS_KEY,
                    REMOTE_CONFIG_WEIGHT_LOCAL_KEY,
                    REMOTE_CONFIG_WEIGHT_REMOTE_KEY,
                    REMOTE_PROCESSING_MAX_KEY,
                    REMOTE_COOLDOWN_SECONDS_KEY,
                ])
            )
        )).scalars().all()
    except Exception as exc:
        logger.error(f"读取远程过滑块配置失败: {exc}")
        return ApiResponse(success=False, message="读取远程过滑块配置失败，请稍后重试")
    m = {r.key: (r.value or "") for r in rows}
    return ApiResponse(success=True, data={
        "url": m.get(REMOTE_CONFIG_URL_KEY, ""),
        "secret_key": m.get(REMOTE_CONFIG_SECRET_KEY, ""),
        "pass_cookies": (m.get(REMOTE_CONFIG_PASS_COOKIES_KEY, "") or "").strip().lower() == "true",
        "block_remote_calls": (m.get(REMOTE_CONFIG_BLOCK_REMOTE_CALLS_KEY, "true") or "true").strip().lower() == "true",
        "local_weight": _sanitize_weight(m.get(REMOTE_CONFIG_WEIGHT_LOCAL_KEY), 1.0),
        "remote_weight": _sanitize_weight(m.get(REMOTE_CONFIG_WEIGHT_REMOTE_KEY), 1.0),
        "remote_processing_max": sanitize_nonnegative_int(
            m.get(REMOTE_PROCESSING_MAX_KEY), DEFAULT_REMOTE_PROCESSING_MAX
        ),
        "remote_cooldown_seconds": sanitize_nonnegative_int(
            m.get(REMOTE_COOLDOWN_SECONDS_KEY), DEFAULT_REMOTE_COOLDOWN_SECONDS
        ),
    })


@router.put("/remote-config")
async def update_remote_config(
    request: RemoteConfigUpdate,
    current_user: User = Depends(deps.get_current_admin_user),  # 仅管理员可写
    db: AsyncSession = Depends(deps.get_db_session),
) -> ApiResponse:
    """保存远程过滑块全局配置（仅管理员，存于 system_settings，全局唯一）。"""
    if request.remote_processing_max is not None and request.remote_processing_max < 0:
        return ApiResponse(success=False, message="远程处理中最大条数不能小于 0")
    if request.remote_cooldown_seconds is not None and request.remote_cooldown_seconds < 0:
        return ApiResponse(success=False, message="远程调用冷却时间不能小于 0")

    # 拦截误填的 Token 获取接口域名，避免把取Token地址配成过滑块服务地址
    remote_url = (request.url or "").strip()
    domain_error = _check_token_api_domain(remote_url)
    if domain_error:
        return domain_error

    settings_to_save: dict[str, tuple[str, str | None]] = {
        REMOTE_CONFIG_URL_KEY: (remote_url, "远程过滑块服务URL"),
        REMOTE_CONFIG_SECRET_KEY: ((request.secret_key or "").strip(), "远程过滑块秘钥"),
        REMOTE_CONFIG_PASS_COOKIES_KEY: (
            "true" if request.pass_cookies else "false",
            "远程过滑块是否传递账号Cookie",
        ),
        REMOTE_CONFIG_BLOCK_REMOTE_CALLS_KEY: (
            "true" if request.block_remote_calls else "false",
            "是否禁止外部远程调用backend-web过滑块接口",
        ),
        # real_mouse 排队权重：规整为非负数后落库，供 websocket 侧调度器读取。
        REMOTE_CONFIG_WEIGHT_LOCAL_KEY: (
            str(_sanitize_weight(request.local_weight, 1.0)),
            "real_mouse过滑块本地排队权重",
        ),
        REMOTE_CONFIG_WEIGHT_REMOTE_KEY: (
            str(_sanitize_weight(request.remote_weight, 1.0)),
            "real_mouse过滑块远程排队权重",
        ),
    }
    if request.remote_processing_max is not None:
        settings_to_save[REMOTE_PROCESSING_MAX_KEY] = (
            str(request.remote_processing_max),
            "远程调用允许的最大处理中滑块日志数，0=不限制",
        )
    if request.remote_cooldown_seconds is not None:
        settings_to_save[REMOTE_COOLDOWN_SECONDS_KEY] = (
            str(request.remote_cooldown_seconds),
            "远程调用达到处理中上限后的冷却秒数，0=不冷却",
        )

    svc = SystemSettingService(db)
    try:
        await svc.set_settings(settings_to_save)
    except Exception as exc:
        await db.rollback()
        logger.error(f"保存远程过滑块配置失败: {exc}")
        return ApiResponse(success=False, message="保存远程过滑块配置失败，请稍后重试")
    return ApiResponse(success=True, message="保存成功")


# ==================== 人工滑块验证（2A，仅管理员） ====================
#
# 自动过滑块失败后（websocket 侧按开关登记「待人工验证」风控日志），管理员在后台
# 「人工验证」页面：查看待处理列表 -> prepare 建会话 -> frame 轮询截图 -> drag 回放轨迹
# -> 通过后由本端写回 Cookie 并重启账号。

MANUAL_FALLBACK_ENABLED_KEY = "captcha.manual_fallback_enabled"


class ManualCaptchaPrepareRequest(BaseModel):
    account_id: str = ""   # 账号标识（cookie_id）


class ManualCaptchaDragRequest(BaseModel):
    track: list[dict] = []
    account_id: str = ""       # 成功后写回 Cookie 与重启账号的标识
    log_id: int | None = None  # 待处理风控日志 ID，成功后标记为 success


class ManualCaptchaInputRequest(BaseModel):
    kind: str = ""              # mousedown / mousemove / mouseup
    x: float = 0.0
    y: float = 0.0
    button: str = "none"        # left / middle / right / none
    buttons: int = 0            # 位掩码：1=左键按下
    clickCount: int = 1


class ManualCaptchaSubmitRequest(BaseModel):
    account_id: str = ""        # 成功后写回 Cookie 与重启账号的标识
    log_id: int | None = None   # 待处理风控日志 ID，成功后标记为 success


async def _finalize_manual_success(
    db: AsyncSession,
    account_id: str,
    log_id: int | None,
    cookies: dict,
) -> dict:
    """人工验证通过后的收尾：写回 x5* Cookie、重启账号、标记待处理日志成功。"""
    from common.services.account_cookie_service import merge_account_cookie_fields
    from common.models.risk_control_log import XYRiskControlLog
    from sqlalchemy import update

    cookie_saved = False
    cookie_message = ""
    restart_message = ""
    if account_id:
        try:
            from app.services.account_service import AccountService

            account = await AccountService(db).get_account_by_identifier(account_id)
            if not account:
                cookie_message = f"账号不存在: {account_id}"
            else:
                saved = await merge_account_cookie_fields(account.id, account_id, cookies)
                if saved:
                    cookie_saved = True
                    cookie_message = "Cookie 已写回数据库"
                else:
                    cookie_message = "Cookie 合并写回失败"
                restart_result = await websocket_client.restart_account(account_id)
                restart_message = (
                    "账号任务已重启" if restart_result.get("success") else
                    f"账号任务重启失败: {restart_result.get('message') or ''}"
                )
        except Exception as exc:
            logger.error(f"人工验证成功后写回Cookie/重启账号失败: account_id={account_id}, 错误: {exc}")
            cookie_message = f"写回Cookie/重启异常: {str(exc)}"

    if log_id:
        try:
            await db.execute(
                update(XYRiskControlLog)
                .where(XYRiskControlLog.id == int(log_id))
                .values(
                    processing_status="success",
                    captcha_engine="manual",
                    processing_result="人工滑块验证通过",
                )
            )
            await db.commit()
        except Exception as exc:
            logger.error(f"标记人工验证日志成功失败: log_id={log_id}, 错误: {exc}")

    return {
        "cookie_saved": cookie_saved,
        "cookie_message": cookie_message,
        "restart_message": restart_message,
    }


@router.get("/manual/pending")
async def list_manual_pending(
    current_user: User = Depends(deps.get_current_admin_user),
    db: AsyncSession = Depends(deps.get_db_session),
) -> ApiResponse:
    """列出待人工验证的风控日志（engine=manual, status=processing，仅管理员）。"""
    from common.models.risk_control_log import XYRiskControlLog
    from common.models.xy_account import XYAccount
    from common.utils.time_utils import safe_isoformat

    try:
        rows = (await db.execute(
            select(XYRiskControlLog, XYAccount.display_name, XYAccount.remark)
            .outerjoin(XYAccount, XYAccount.id == XYRiskControlLog.account_pk)
            .where(
                XYRiskControlLog.captcha_engine == "manual",
                XYRiskControlLog.processing_status == "processing",
            )
            .order_by(XYRiskControlLog.created_at.desc())
            .limit(100)
        )).all()

        items = [
            {
                "id": log.id,
                "account_id": log.account_identifier,
                "account_pk": log.account_pk,
                "display_name": display_name or "",
                "remark": remark or "",
                "error_message": log.error_message,
                "created_at": safe_isoformat(log.created_at),
            }
            for log, display_name, remark in rows
        ]
        return ApiResponse(success=True, data=items)
    except Exception as exc:
        logger.error(f"加载人工验证待处理列表失败: {exc}")
        return ApiResponse(success=False, message=f"加载人工验证待处理列表失败: {str(exc)}")


@router.post("/manual/prepare")
async def manual_captcha_prepare(
    request: ManualCaptchaPrepareRequest,
    current_user: User = Depends(deps.get_current_admin_user),
    db: AsyncSession = Depends(deps.get_db_session),
) -> ApiResponse:
    """创建人工验证会话（仅管理员）。返回 session_id 供截图/拖动使用。"""
    account_id = (request.account_id or "").strip()
    if not account_id:
        return ApiResponse(success=False, message="缺少账号标识")

    try:
        from app.services.account_service import AccountService

        account = await AccountService(db).get_account_by_identifier(account_id)
        if not account:
            return ApiResponse(success=False, message=f"账号不存在: {account_id}")
        cookie_value = account.cookie or ""
        if not cookie_value:
            return ApiResponse(success=False, message=f"账号 {account_id} 未配置 Cookie")

        result = await websocket_client.manual_captcha_prepare(
            account_id=account_id,
            cookies=cookie_value,
            device_id="",
        )
    except Exception as exc:
        logger.error(f"创建人工验证会话失败: account_id={account_id}, 错误: {exc}")
        return ApiResponse(success=False, message=f"创建人工验证会话失败: {str(exc)}")

    if not (isinstance(result, dict) and result.get("success")):
        msg = (result or {}).get("message") if isinstance(result, dict) else None
        return ApiResponse(success=False, message=msg or "创建人工验证会话失败")
    return ApiResponse(
        success=True,
        message="人工验证会话已就绪",
        data={"session_id": result["data"]["session_id"], "account_id": account_id},
    )


@router.get("/manual/{session_id}/frame")
async def manual_captcha_frame(
    session_id: str,
    current_user: User = Depends(deps.get_current_admin_user),
) -> ApiResponse:
    """截取人工验证会话的滑块页面（base64 JPEG）。"""
    result = await websocket_client.manual_captcha_frame(session_id)
    if not (isinstance(result, dict) and result.get("success")):
        msg = (result or {}).get("message") if isinstance(result, dict) else None
        return ApiResponse(success=False, message=msg or "获取截图失败")
    return ApiResponse(success=True, data=result["data"])


@router.post("/manual/{session_id}/drag")
async def manual_captcha_drag(
    session_id: str,
    request: ManualCaptchaDragRequest,
    current_user: User = Depends(deps.get_current_admin_user),
    db: AsyncSession = Depends(deps.get_db_session),
) -> ApiResponse:
    """回放人工轨迹；通过时写回 Cookie、重启账号并标记待处理日志成功。"""
    account_id = (request.account_id or "").strip()
    log_id = request.log_id

    result = await websocket_client.manual_captcha_drag(session_id, request.track)
    if not (isinstance(result, dict) and result.get("success")):
        msg = (result or {}).get("message") if isinstance(result, dict) else None
        return ApiResponse(success=False, message=msg or "回放轨迹失败")

    data = result.get("data") or {}
    passed = bool(data.get("passed"))
    cookies = data.get("cookies")

    if not (passed and cookies):
        # 未通过：让前端继续轮询截图重试，待处理日志保持 processing
        return ApiResponse(
            success=True,
            message="验证未通过，可重试",
            data={"passed": False},
        )

    # 通过：写回 x5* Cookie、重启账号并标记待处理日志成功
    finalize = await _finalize_manual_success(db, account_id, log_id, cookies)
    return ApiResponse(
        success=True,
        message="验证通过",
        data={"passed": True, **finalize},
    )


@router.post("/manual/{session_id}/close")
async def manual_captcha_close(
    session_id: str,
    current_user: User = Depends(deps.get_current_admin_user),
) -> ApiResponse:
    """关闭人工验证会话并释放资源。"""
    result = await websocket_client.manual_captcha_close(session_id)
    return ApiResponse(success=True, message="会话已关闭")


@router.post("/manual/{session_id}/input")
async def manual_captcha_input(
    session_id: str,
    request: ManualCaptchaInputRequest,
    current_user: User = Depends(deps.get_current_admin_user),
) -> ApiResponse:
    """实时转发人工鼠标事件到真实页面（仅管理员）。"""
    result = await websocket_client.manual_captcha_input(
        session_id,
        {
            "kind": request.kind,
            "x": request.x,
            "y": request.y,
            "button": request.button,
            "buttons": request.buttons,
            "clickCount": request.clickCount,
        },
    )
    if not (isinstance(result, dict) and result.get("success")):
        msg = (result or {}).get("message") if isinstance(result, dict) else None
        return ApiResponse(success=False, message=msg or "转发输入事件失败")
    return ApiResponse(success=True, data=result.get("data"))


@router.post("/manual/{session_id}/submit")
async def manual_captcha_submit(
    session_id: str,
    request: ManualCaptchaSubmitRequest,
    current_user: User = Depends(deps.get_current_admin_user),
    db: AsyncSession = Depends(deps.get_db_session),
) -> ApiResponse:
    """判定人工验证结果；通过时写回 Cookie、重启账号并标记日志成功（仅管理员）。"""
    account_id = (request.account_id or "").strip()
    log_id = request.log_id

    result = await websocket_client.manual_captcha_check(session_id)
    if not (isinstance(result, dict) and result.get("success")):
        msg = (result or {}).get("message") if isinstance(result, dict) else None
        return ApiResponse(success=False, message=msg or "判定验证结果失败")

    data = result.get("data") or {}
    passed = bool(data.get("passed"))
    cookies = data.get("cookies")

    if not (passed and cookies):
        # 未通过：保持流式，管理员可直接再拖一次
        return ApiResponse(success=True, message="验证未通过，可重试", data={"passed": False})

    finalize = await _finalize_manual_success(db, account_id, log_id, cookies)
    return ApiResponse(
        success=True,
        message="验证通过",
        data={"passed": True, **finalize},
    )


@router.websocket("/manual/{session_id}/stream")
async def manual_captcha_stream(
    websocket: WebSocket,
    session_id: str,
    token: str | None = Query(default=None),
):
    """人工验证实时流（仅管理员）。

    下行：以 ~8fps 轮询 websocket 服务的截图并推送 frame 事件。
    上行：接收 input 事件并实时转发到真实页面；支持 ping 心跳。
    """
    from app.core.security import decode_token
    from jose import JWTError
    from common.models import UserRole, UserStatus
    from common.schemas.auth import TokenPayload

    await websocket.accept()

    # 鉴权：先 accept 再校验，确保自定义关闭码能通过 WebSocket 关闭帧送达浏览器
    if not token:
        await websocket.close(code=4401)
        return
    try:
        payload = TokenPayload(**decode_token(token))
        user_id = int(payload.sub)
    except (JWTError, ValueError, TypeError):
        await websocket.close(code=4401)
        return

    async with async_session_maker() as session:
        result = await session.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
    if not user or user.status != UserStatus.ACTIVE or user.role != UserRole.ADMIN:
        await websocket.close(code=4403)
        return

    logger.info(f"【{session_id}】人工验证实时流已连接（管理员 {user.id}）")

    FRAME_INTERVAL = 0.125  # 8fps

    async def pump_frames() -> None:
        while True:
            try:
                res = await websocket_client.manual_captcha_frame(session_id)
                if isinstance(res, dict) and res.get("success"):
                    await websocket.send_text(json.dumps(
                        {"event": "frame", "data": res.get("data")},
                        ensure_ascii=False,
                    ))
                else:
                    msg = (res or {}).get("message", "截图失败") if isinstance(res, dict) else "截图失败"
                    await websocket.send_text(json.dumps(
                        {"event": "error", "message": msg},
                        ensure_ascii=False,
                    ))
            except WebSocketDisconnect:
                break
            except Exception as exc:  # noqa: BLE001
                logger.error(f"【{session_id}】人工验证流截图失败: {exc}")
            await asyncio.sleep(FRAME_INTERVAL)

    pump_task = asyncio.create_task(pump_frames())

    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
            except json.JSONDecodeError:
                continue

            msg_type = msg.get("type", "")
            if msg_type == "ping":
                await websocket.send_text(json.dumps({"event": "pong"}, ensure_ascii=False))
            elif msg_type == "input":
                event = msg.get("event") or {}
                await websocket_client.manual_captcha_input(session_id, event)
            else:
                logger.info(f"【{session_id}】人工验证流收到未知消息类型: {msg_type}")
    except WebSocketDisconnect:
        logger.info(f"【{session_id}】人工验证实时流已断开")
    except Exception as exc:  # noqa: BLE001
        logger.error(f"【{session_id}】人工验证实时流异常: {exc}")
    finally:
        pump_task.cancel()
        try:
            await pump_task
        except asyncio.CancelledError:
            pass
        logger.info(f"【{session_id}】人工验证实时流已清理")


@router.post("/manual/pending/{log_id}/dismiss")
async def dismiss_manual_pending(
    log_id: int,
    current_user: User = Depends(deps.get_current_admin_user),
    db: AsyncSession = Depends(deps.get_db_session),
) -> ApiResponse:
    """放弃某条待人工验证记录（标记为 failed），使其退出待处理列表。"""
    from common.models.risk_control_log import XYRiskControlLog
    from sqlalchemy import update

    try:
        result = await db.execute(
            update(XYRiskControlLog)
            .where(
                XYRiskControlLog.id == int(log_id),
                XYRiskControlLog.captcha_engine == "manual",
                XYRiskControlLog.processing_status == "processing",
            )
            .values(
                processing_status="failed",
                processing_result="人工验证已放弃",
            )
        )
        await db.commit()
        if not result.rowcount:
            return ApiResponse(success=False, message="待处理记录不存在或已处理")
        return ApiResponse(success=True, message="已放弃该条人工验证")
    except Exception as exc:
        logger.error(f"放弃人工验证记录失败: log_id={log_id}, 错误: {exc}")
        return ApiResponse(success=False, message=f"放弃人工验证记录失败: {str(exc)}")


@router.get("/manual/config")
async def get_manual_fallback_config(
    current_user: User = Depends(deps.get_current_admin_user),
    setting_service: SystemSettingService = Depends(deps.get_system_setting_service),
) -> ApiResponse:
    """读取人工滑块兜底开关（仅管理员）。"""
    try:
        settings = await setting_service.list_settings()
        enabled = str(settings.get(MANUAL_FALLBACK_ENABLED_KEY, "false")).strip().lower() == "true"
        return ApiResponse(success=True, data={"enabled": enabled})
    except Exception as exc:
        logger.error(f"读取人工滑块兜底开关失败: {exc}")
        return ApiResponse(success=False, message=f"读取人工滑块兜底开关失败: {str(exc)}")


class ManualFallbackConfigUpdate(BaseModel):
    enabled: bool


@router.put("/manual/config")
async def update_manual_fallback_config(
    request: ManualFallbackConfigUpdate,
    current_user: User = Depends(deps.get_current_admin_user),
    setting_service: SystemSettingService = Depends(deps.get_system_setting_service),
) -> ApiResponse:
    """更新人工滑块兜底开关（仅管理员）。"""
    try:
        await setting_service.set_setting(
            MANUAL_FALLBACK_ENABLED_KEY,
            "true" if request.enabled else "false",
            "自动过滑块失败后是否登记人工验证待处理并在后台提供人工验证入口",
        )
        return ApiResponse(
            success=True,
            message="人工滑块兜底已开启" if request.enabled else "人工滑块兜底已关闭",
            data={"enabled": request.enabled},
        )
    except Exception as exc:
        logger.error(f"更新人工滑块兜底开关失败: {exc}")
        return ApiResponse(success=False, message=f"更新人工滑块兜底开关失败: {str(exc)}")
