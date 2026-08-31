"""
人工滑块验证 - 会话管理器

当自动过滑块失败后，本模块在 websocket 进程内持有一个真实浏览器页面，
把滑块页面截图提供给后台前端，人工拖动后回放其真实鼠标轨迹，拿回 x5sec cookie。

设计要点：
1. 复用 PlaywrightSliderService（并发槽位 + 账号级互斥锁 + patchright/stealth 启动 + cookie 提取）。
2. sync Playwright 对象绑定其创建线程，因此每个会话跑在独立线程上，用 queue.Queue
   作为命令通道，异步事件循环通过 asyncio.to_thread 等待结果，避免跨线程驱动浏览器。
3. punish 链接 TTL 短：prepare 阶段调用 request_fresh_captcha_url 现取新鲜链接，
   而不是复用触发风控时的旧链接。
"""
from __future__ import annotations

import base64
import queue
import threading
import time
import uuid
from typing import Any, Dict, Optional

from loguru import logger

from common.services.captcha.slider_stealth import PlaywrightSliderService
from common.services.captcha.token_refetch import request_fresh_captcha_url
from common.utils.xianyu_utils import trans_cookies

# 会话最长存活时间（秒）：超过后自动关闭并释放浏览器槽位/账号锁。
# 人工拖滑块通常几秒到几十秒内完成，3 分钟足够并避免长期占用资源。
SESSION_TTL_SECONDS = 180
# prepare 阶段等待浏览器就绪的上限（含并发槽位等待 + 浏览器启动）。
PREPARE_TIMEOUT_SECONDS = 90


class ManualSession:
    """单个人工验证会话（对应一个账号的一次滑块挑战）。"""

    def __init__(self, account_id: str, cookies_str: str, device_id: str = ""):
        self.session_id = uuid.uuid4().hex
        self.account_id = str(account_id)
        self.cookies_str = cookies_str or ""
        self.device_id = device_id or ""
        self.created_at = time.time()

        self._queue: "queue.Queue[tuple[str, Any, dict]]" = queue.Queue()
        self._ready_event = threading.Event()
        self._ready_error: Optional[str] = None
        self._closed = False

        self._service: Optional[PlaywrightSliderService] = None
        self._page: Any = None
        self._cdp_session: Any = None  # 懒创建的 CDP 会话，用于实时鼠标输入派发

        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name=f"manual-captcha-{self.session_id[:8]}",
        )

    # ---- 对外命令接口（由异步事件循环调用，内部会阻塞等待结果） ----
    def start(self) -> None:
        self._thread.start()

    def wait_ready(self, timeout: float = PREPARE_TIMEOUT_SECONDS) -> None:
        """等待浏览器就绪；失败抛异常。"""
        if not self._ready_event.wait(timeout):
            raise TimeoutError(f"人工验证会话准备超时（{timeout:.0f}秒），账号浏览器可能繁忙")
        if self._ready_error:
            raise RuntimeError(self._ready_error)

    def execute(self, cmd: str, payload: Any = None, timeout: float = 30.0) -> Any:
        if self._closed:
            raise RuntimeError("人工验证会话已关闭")
        if self._ready_error:
            raise RuntimeError(self._ready_error)
        holder: Dict[str, Any] = {"result": None, "error": None, "done": threading.Event()}
        self._queue.put((cmd, payload, holder))
        if not holder["done"].wait(timeout):
            raise TimeoutError(f"人工验证命令超时: {cmd}")
        if holder["error"]:
            raise RuntimeError(holder["error"])
        return holder["result"]

    def request_close(self) -> None:
        self._closed = True

    # ---- 会话线程主体 ----
    def _run(self) -> None:
        try:
            # 1. 建服务（阻塞等待并发槽位 + 账号锁）
            svc = PlaywrightSliderService(
                user_id=self.account_id,
                enable_learning=False,
                headless=True,
            )
            self._service = svc

            # 2. 现取新鲜 punish 链接（旧链接此时多半已过期）
            fresh_url = self._fetch_fresh_url()
            if not fresh_url:
                self._ready_error = (
                    "无法获取新鲜的滑块验证链接（风控可能已解除或账号状态异常），请稍后重试"
                )
                self._ready_event.set()
                return

            # 3. 启动浏览器并导航到滑块页
            self._page = svc.init_browser(add_stealth_script=True)
            self._page.goto(fresh_url, wait_until="domcontentloaded", timeout=15000)
            time.sleep(1.5)  # 等滑块资源渲染
            logger.info(f"【{self.account_id}】人工验证会话就绪: {self.session_id[:8]}")
            self._ready_event.set()

            # 4. 命令循环
            while not self._closed:
                try:
                    cmd, payload, holder = self._queue.get(timeout=1.0)
                except queue.Empty:
                    self._check_ttl()
                    continue
                try:
                    holder["result"] = self._handle(cmd, payload)
                except Exception as exc:  # noqa: BLE001
                    logger.warning(f"【{self.account_id}】人工验证命令 {cmd} 失败: {exc}")
                    holder["error"] = str(exc)
                finally:
                    holder["done"].set()
        except Exception as exc:  # noqa: BLE001
            logger.error(f"【{self.account_id}】人工验证会话异常: {exc}")
            self._ready_error = str(exc)
            self._ready_event.set()
        finally:
            self._cleanup()

    def _fetch_fresh_url(self) -> Optional[str]:
        cookies_dict = trans_cookies(self.cookies_str) or {}
        res = request_fresh_captcha_url(
            self.account_id,
            cookies_dict,
            self.cookies_str,
            self.device_id,
        )
        if res.get("token_ok"):
            logger.info(f"【{self.account_id}】重取链接时风控已解除，无需滑块")
            return None
        return res.get("fresh_url")

    def _handle(self, cmd: str, payload: Any) -> Any:
        if cmd == "frame":
            return self._handle_frame()
        if cmd == "input":
            return self._handle_input(payload)
        if cmd == "check":
            return self._handle_check()
        if cmd == "drag":
            return self._handle_drag(payload)
        if cmd == "close":
            self.request_close()
            return {"closed": True}
        raise ValueError(f"未知命令: {cmd}")

    def _handle_frame(self) -> Dict[str, Any]:
        if not self._page:
            raise RuntimeError("会话未就绪")
        data = self._page.screenshot(type="jpeg", quality=55)
        b64 = base64.b64encode(data).decode("ascii")
        vp = self._page.viewport_size or {"width": 1920, "height": 1080}
        return {
            "image_b64": b64,
            "width": int(vp.get("width") or 1920),
            "height": int(vp.get("height") or 1080),
        }

    def _handle_input(self, event: Any) -> Dict[str, Any]:
        """实时派发单个鼠标事件（通过 CDP Input.dispatchMouseEvent）。

        与「采样轨迹后回放」不同，这里把前端人工拖动的每一次 mousedown/move/up
        原样、实时地打进真实页面，保留人类真实时序，页面即时反馈。
        """
        if not self._page:
            raise RuntimeError("会话未就绪")
        if not isinstance(event, dict):
            raise ValueError("输入事件格式错误")

        kind = str(event.get("kind") or "")
        x = float(event.get("x") or 0)
        y = float(event.get("y") or 0)
        button = str(event.get("button") or "none")
        buttons = int(event.get("buttons") or 0)
        click_count = int(event.get("clickCount") or 1)

        cdp_type = {
            "mousedown": "mousePressed",
            "mousemove": "mouseMoved",
            "mouseup": "mouseReleased",
        }.get(kind)
        if cdp_type is None:
            raise ValueError(f"不支持的鼠标事件类型: {kind}")

        if self._cdp_session is None:
            self._cdp_session = self._page.context.new_cdp_session(self._page)

        self._cdp_session.send(
            "Input.dispatchMouseEvent",
            {
                "type": cdp_type,
                "x": x,
                "y": y,
                "button": button,
                "buttons": buttons,
                "clickCount": click_count,
                "modifiers": 0,
            },
        )
        return {"ok": True}

    def _handle_check(self) -> Dict[str, Any]:
        """判定是否通过：等待页面稳定后读取 x5* Cookie。"""
        if not self._page:
            raise RuntimeError("会话未就绪")
        time.sleep(0.5)  # 等页面在 mouseup 后稳定/跳转
        cookies = self._service._get_cookies_after_success() if self._service else None
        if cookies:
            logger.success(f"【{self.account_id}】人工滑块验证通过")
            return {"passed": True, "cookies": cookies}
        logger.info(f"【{self.account_id}】人工滑块未通过，可重试")
        return {"passed": False, "cookies": None}

    def _handle_drag(self, track: Any) -> Dict[str, Any]:
        if not self._page:
            raise RuntimeError("会话未就绪")
        if not track or len(track) < 2:
            raise ValueError("轨迹点不足，无法回放")

        pts = [
            (float(p.get("x")), float(p.get("y")), max(0.0, float(p.get("t") or 0)))
            for p in track
        ]
        page = self._page

        # 按真人轨迹与时间戳逐点回放（轨迹来自前端人工拖动采样）
        start = time.monotonic()
        page.mouse.move(pts[0][0], pts[0][1])
        page.mouse.down()
        for x, y, t in pts[1:-1]:
            wait = (start + t / 1000.0) - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            page.mouse.move(x, y)
        page.mouse.move(pts[-1][0], pts[-1][1])
        time.sleep(0.05)
        page.mouse.up()

        # 等待结果并判定（内部会校验 URL 是否已跳离 punish + 是否拿到 x5sec）
        time.sleep(1.0)
        cookies = self._service._get_cookies_after_success() if self._service else None
        if cookies:
            logger.success(f"【{self.account_id}】人工滑块验证通过")
            return {"passed": True, "cookies": cookies}
        logger.info(f"【{self.account_id}】人工滑块未通过，可重试")
        return {"passed": False, "cookies": None}

    def _check_ttl(self) -> None:
        if time.time() - self.created_at > SESSION_TTL_SECONDS:
            logger.warning(f"【{self.account_id}】人工验证会话超时，自动关闭")
            self.request_close()

    def _cleanup(self) -> None:
        self._closed = True
        if self._service is not None:
            try:
                self._service.close()
            except Exception as exc:  # noqa: BLE001
                logger.warning(f"【{self.account_id}】人工验证会话清理失败: {exc}")
            self._service = None
        self._page = None
        logger.info(f"【{self.account_id}】人工验证会话已关闭")


class ManualCaptchaController:
    """人工验证会话注册表（进程内单例）。"""

    def __init__(self):
        self._sessions: Dict[str, ManualSession] = {}
        self._lock = threading.Lock()

    def create(self, account_id: str, cookies_str: str, device_id: str = "") -> ManualSession:
        self._cleanup_expired()
        session = ManualSession(account_id, cookies_str, device_id)
        with self._lock:
            self._sessions[session.session_id] = session
        session.start()
        session.wait_ready()
        return session

    def get(self, session_id: str) -> ManualSession:
        with self._lock:
            session = self._sessions.get(session_id)
        if session is None:
            raise KeyError(f"人工验证会话不存在或已关闭: {session_id}")
        return session

    def close(self, session_id: str) -> None:
        with self._lock:
            session = self._sessions.pop(session_id, None)
        if session is not None:
            session.request_close()

    def _cleanup_expired(self) -> None:
        now = time.time()
        with self._lock:
            expired = [
                sid for sid, s in self._sessions.items()
                if now - s.created_at > SESSION_TTL_SECONDS
            ]
        for sid in expired:
            self.close(sid)


# 进程内单例
manual_captcha_controller = ManualCaptchaController()
