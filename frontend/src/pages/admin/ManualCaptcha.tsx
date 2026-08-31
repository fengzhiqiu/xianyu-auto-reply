/**
 * 人工滑块验证页面（2A - 实时远程操控版）
 *
 * 功能：
 * 1. 展示「待人工验证」列表（自动过滑块失败后由 websocket 侧登记）。
 * 2. 管理员点击「处理」→ 创建浏览器会话并现取新鲜滑块链接。
 * 3. 通过 WebSocket 实时接收浏览器画面（~8fps），管理员真实拖动滑块，
 *    每次鼠标事件实时转发给真实浏览器（不再采样/回放，滑块实时跟手）。
 * 4. 松开鼠标后自动判定；通过后由后端写回 x5* Cookie 并重启账号。
 */
import { useCallback, useEffect, useRef, useState, type MouseEvent as ReactMouseEvent } from 'react'
import { Loader2, RefreshCw, Info, ShieldAlert, X, Wifi, WifiOff } from 'lucide-react'
import { useAuthStore } from '@/store/authStore'
import { useUIStore } from '@/store/uiStore'
import { useManualCaptchaStore } from '@/store/manualCaptchaStore'
import { PageLoading } from '@/components/common/Loading'
import { getApiErrorMessage } from '@/utils/request'
import {
  getManualCaptchaPending,
  prepareManualCaptcha,
  closeManualCaptcha,
  dismissManualCaptcha,
  getManualFallbackConfig,
  updateManualFallbackConfig,
  createManualCaptchaStreamWs,
  submitManualCaptcha,
  type ManualCaptchaPendingItem,
  type ManualCaptchaFrame,
} from '@/api/admin'

interface Point {
  x: number
  y: number
}

export function ManualCaptcha() {
  const { addToast } = useUIStore()
  const { isAuthenticated, token, _hasHydrated, user } = useAuthStore()
  const { refreshPendingCount } = useManualCaptchaStore()

  const [loading, setLoading] = useState(true)
  const [pending, setPending] = useState<ManualCaptchaPendingItem[]>([])
  const [preparing, setPreparing] = useState(false)

  // 当前正在处理的会话
  const [activeItem, setActiveItem] = useState<ManualCaptchaPendingItem | null>(null)
  const [sessionId, setSessionId] = useState<string | null>(null)
  const [frame, setFrame] = useState<ManualCaptchaFrame | null>(null)
  const [frameError, setFrameError] = useState('')
  const [connected, setConnected] = useState(false)
  const [dragging, setDragging] = useState(false)
  const [submitting, setSubmitting] = useState(false)

  // 人工滑块兜底开关
  const [fallbackEnabled, setFallbackEnabled] = useState(false)
  const [configLoading, setConfigLoading] = useState(true)
  const [savingConfig, setSavingConfig] = useState(false)

  // 实时流 / 拖动相关 ref
  const imgRef = useRef<HTMLImageElement | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const draggingRef = useRef(false)
  const submittingRef = useRef(false)
  const lastMoveAtRef = useRef(0)
  const pingTimerRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const loadPending = useCallback(async () => {
    if (!_hasHydrated || !isAuthenticated || !token) return
    try {
      setLoading(true)
      const res = await getManualCaptchaPending()
      if (res.success) {
        setPending(res.data || [])
      } else {
        addToast({ type: 'error', message: res.message || '加载待处理列表失败' })
      }
    } catch (error) {
      addToast({ type: 'error', message: getApiErrorMessage(error, '加载待处理列表失败') })
    } finally {
      setLoading(false)
    }
  }, [_hasHydrated, isAuthenticated, token, addToast])

  const loadConfig = useCallback(async () => {
    if (!_hasHydrated || !isAuthenticated || !token || !user?.is_admin) {
      setConfigLoading(false)
      return
    }
    try {
      setConfigLoading(true)
      const res = await getManualFallbackConfig()
      if (res.success && res.data) {
        setFallbackEnabled(Boolean(res.data.enabled))
      }
    } catch {
      // 忽略失败
    } finally {
      setConfigLoading(false)
    }
  }, [_hasHydrated, isAuthenticated, token, user?.is_admin])

  useEffect(() => {
    loadPending()
    loadConfig()
  }, [loadPending, loadConfig])

  const closeSession = useCallback(async () => {
    if (wsRef.current) {
      wsRef.current.onmessage = null
      wsRef.current.onclose = null
      wsRef.current.onerror = null
      wsRef.current.close()
      wsRef.current = null
    }
    if (pingTimerRef.current) {
      clearInterval(pingTimerRef.current)
      pingTimerRef.current = null
    }
    if (sessionId) {
      try {
        await closeManualCaptcha(sessionId)
      } catch {
        // 关闭失败忽略
      }
    }
    setSessionId(null)
    setActiveItem(null)
    setFrame(null)
    setFrameError('')
    setConnected(false)
    setDragging(false)
  }, [sessionId])

  const openStream = useCallback((sid: string) => {
    const ws = createManualCaptchaStreamWs(sid)
    wsRef.current = ws
    setFrame(null)
    setFrameError('')
    setConnected(false)

    ws.onopen = () => setConnected(true)
    ws.onmessage = (ev) => {
      let msg: { event?: string; data?: ManualCaptchaFrame; message?: string }
      try {
        msg = JSON.parse(ev.data)
      } catch {
        return
      }
      if (msg.event === 'frame' && msg.data) {
        setFrame(msg.data)
        setFrameError('')
      } else if (msg.event === 'error') {
        setFrameError(msg.message || '截图失败')
      }
      // pong / 其它事件忽略
    }
    ws.onclose = () => setConnected(false)
    ws.onerror = () => setConnected(false)

    // 心跳保活
    pingTimerRef.current = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'ping' }))
      }
    }, 25000)
  }, [])

  // 页面卸载时关闭会话与 WS
  useEffect(() => {
    return () => {
      if (sessionId) {
        void closeManualCaptcha(sessionId)
      }
      if (wsRef.current) {
        wsRef.current.close()
      }
    }
  }, [sessionId])

  const handleSolve = async (item: ManualCaptchaPendingItem) => {
    if (sessionId) {
      await closeSession()
    }
    setPreparing(true)
    try {
      const res = await prepareManualCaptcha(item.account_id)
      if (res.success && res.data?.session_id) {
        setActiveItem(item)
        setSessionId(res.data.session_id)
        openStream(res.data.session_id)
      } else {
        addToast({ type: 'error', message: res.message || '创建人工验证会话失败' })
      }
    } catch (error) {
      addToast({ type: 'error', message: getApiErrorMessage(error, '创建人工验证会话失败') })
    } finally {
      setPreparing(false)
    }
  }

  const handleDismiss = async (item: ManualCaptchaPendingItem) => {
    try {
      const res = await dismissManualCaptcha(item.id)
      addToast({ type: res.success ? 'success' : 'error', message: res.message || '已放弃该条人工验证' })
      loadPending()
      void refreshPendingCount()
    } catch (error) {
      addToast({ type: 'error', message: getApiErrorMessage(error, '放弃失败') })
    }
  }

  const sendInput = (event: Record<string, unknown>) => {
    const ws = wsRef.current
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'input', event }))
    }
  }

  const handleSubmit = async () => {
    if (!sessionId || !activeItem || submittingRef.current) return
    submittingRef.current = true
    setSubmitting(true)
    try {
      // 松开后稍等页面判定/跳转，再检查结果
      await new Promise((r) => setTimeout(r, 1200))
      const res = await submitManualCaptcha(sessionId, activeItem.account_id, activeItem.id)
      if (res.success && res.data?.passed) {
        addToast({
          type: 'success',
          message: res.data.cookie_message || '验证通过，Cookie 已写回并重启账号',
        })
        await closeSession()
        loadPending()
        void refreshPendingCount()
      } else {
        addToast({ type: 'warning', message: res.message || '验证未通过，可继续拖动重试' })
        // 保持流式，滑块页面会实时复位，管理员直接再拖一次
      }
    } catch (error) {
      addToast({ type: 'error', message: getApiErrorMessage(error, '判定结果失败') })
    } finally {
      submittingRef.current = false
      setSubmitting(false)
    }
  }

  // ---- 实时鼠标输入采样（不做轨迹回放，只做坐标换算后原样转发） ----
  const getNaturalPoint = (e: MouseEvent): Point | null => {
    const img = imgRef.current
    if (!img || !img.naturalWidth || !img.naturalHeight) return null
    const rect = img.getBoundingClientRect()
    if (rect.width <= 0 || rect.height <= 0) return null
    return {
      x: Math.round(((e.clientX - rect.left) / rect.width) * img.naturalWidth),
      y: Math.round(((e.clientY - rect.top) / rect.height) * img.naturalHeight),
    }
  }

  const handleMouseDown = (e: ReactMouseEvent<HTMLImageElement>) => {
    if (submittingRef.current) return
    const p = getNaturalPoint(e.nativeEvent)
    if (!p) return
    e.preventDefault()
    draggingRef.current = true
    setDragging(true)
    lastMoveAtRef.current = 0
    sendInput({ kind: 'mousedown', x: p.x, y: p.y, button: 'left', buttons: 1, clickCount: 1 })
    window.addEventListener('mousemove', handleWindowMouseMove)
    window.addEventListener('mouseup', handleWindowMouseUp)
  }

  const handleWindowMouseMove = (e: MouseEvent) => {
    // 轻节流，避免刷爆通道（~60Hz 足够）
    const now = performance.now()
    if (now - lastMoveAtRef.current < 16) return
    lastMoveAtRef.current = now
    const p = getNaturalPoint(e)
    if (!p) return
    sendInput({ kind: 'mousemove', x: p.x, y: p.y, button: 'none', buttons: 1 })
  }

  const handleWindowMouseUp = (e: MouseEvent) => {
    window.removeEventListener('mousemove', handleWindowMouseMove)
    window.removeEventListener('mouseup', handleWindowMouseUp)
    const p = getNaturalPoint(e)
    if (p) {
      sendInput({ kind: 'mouseup', x: p.x, y: p.y, button: 'left', buttons: 0, clickCount: 1 })
    }
    draggingRef.current = false
    setDragging(false)
    void handleSubmit()
  }

  const handleConfigChange = async () => {
    const next = !fallbackEnabled
    try {
      setSavingConfig(true)
      const res = await updateManualFallbackConfig(next)
      if (res.success) {
        setFallbackEnabled(res.data?.enabled ?? next)
        addToast({ type: 'success', message: res.message || (next ? '人工滑块兜底已开启' : '人工滑块兜底已关闭') })
      } else {
        addToast({ type: 'error', message: res.message || '更新开关失败' })
      }
    } catch (error) {
      addToast({ type: 'error', message: getApiErrorMessage(error, '更新开关失败') })
    } finally {
      setSavingConfig(false)
    }
  }

  if (loading) {
    return <PageLoading />
  }

  const frameSrc = frame ? `data:image/jpeg;base64,${frame.image_b64}` : ''

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="page-title">人工验证</h1>
          <p className="page-description">自动过滑块失败后，在此实时远程操控浏览器完成滑块验证</p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-sm font-medium text-slate-700 dark:text-slate-200">人工滑块兜底</span>
          <button
            type="button"
            onClick={handleConfigChange}
            disabled={configLoading || savingConfig}
            role="switch"
            aria-checked={fallbackEnabled}
            className={`relative inline-flex h-5 w-10 shrink-0 items-center rounded-full transition-colors disabled:cursor-not-allowed disabled:opacity-60 ${
              fallbackEnabled ? 'bg-blue-500' : 'bg-gray-300 dark:bg-slate-600'
            }`}
          >
            {configLoading || savingConfig ? (
              <Loader2 className="absolute left-3.5 h-3 w-3 animate-spin text-white" />
            ) : (
              <span
                className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                  fallbackEnabled ? 'translate-x-5' : 'translate-x-0.5'
                }`}
              />
            )}
          </button>
          <button onClick={() => { loadPending(); void refreshPendingCount() }} className="btn-ios-secondary">
            <RefreshCw className="w-4 h-4" />
            刷新
          </button>
        </div>
      </div>

      <div className="rounded-lg border border-blue-200 bg-blue-50 px-4 py-3 dark:border-blue-500/30 dark:bg-blue-500/10">
        <div className="flex items-start gap-2">
          <Info className="w-4 h-4 mt-0.5 shrink-0 text-blue-500 dark:text-blue-400" />
          <p className="text-sm text-blue-700 dark:text-blue-300">
            开启「人工滑块兜底」后，账号自动过滑块失败会在此登记待处理记录。点击「处理」后会在下方实时显示真实浏览器画面，直接拖动画面中的滑块即可；滑块会实时跟手，松开后自动判定，通过后 Cookie 自动写回并重启账号。
          </p>
        </div>
      </div>

      {/* 待处理列表 */}
      <div className="vben-card">
        <div className="vben-card-header">
          <h2 className="vben-card-title">
            <ShieldAlert className="w-4 h-4 text-amber-500" />
            待人工验证
          </h2>
          <span className="badge-primary">{pending.length} 条</span>
        </div>
        <div className="overflow-auto">
          <table className="table-ios">
            <thead>
              <tr>
                <th>账号</th>
                <th>备注</th>
                <th>登记时间</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {pending.length === 0 ? (
                <tr>
                  <td colSpan={4} className="text-center py-8 text-slate-500 dark:text-slate-400">
                    暂无待人工验证记录
                  </td>
                </tr>
              ) : (
                pending.map((item) => (
                  <tr key={item.id}>
                    <td className="font-medium text-blue-600 dark:text-blue-400">{item.account_id}</td>
                    <td className="text-slate-600 dark:text-slate-300">{item.remark || item.display_name || '-'}</td>
                    <td className="text-slate-500 dark:text-slate-400 text-sm whitespace-nowrap">
                      {item.created_at ? new Date(item.created_at).toLocaleString() : '-'}
                    </td>
                    <td>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => handleSolve(item)}
                          disabled={preparing}
                          className="btn-ios-primary disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          {preparing ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
                          处理
                        </button>
                        <button onClick={() => handleDismiss(item)} className="btn-ios-secondary">
                          放弃
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* 验证面板 */}
      {activeItem && sessionId && (
        <div className="vben-card">
          <div className="vben-card-header">
            <h2 className="vben-card-title">
              <ShieldAlert className="w-4 h-4 text-blue-500" />
              验证账号：{activeItem.account_id}
              {activeItem.remark ? ` (${activeItem.remark})` : ''}
            </h2>
            <div className="flex items-center gap-3">
              <span className="flex items-center gap-1.5 text-sm text-slate-500 dark:text-slate-400">
                {connected ? (
                  <>
                    <Wifi className="w-4 h-4 text-green-500" />
                    已连接
                  </>
                ) : (
                  <>
                    <WifiOff className="w-4 h-4 text-red-500" />
                    连接中…
                  </>
                )}
              </span>
              <button onClick={() => { void closeSession(); loadPending() }} className="btn-ios-secondary">
                <X className="w-4 h-4" />
                关闭会话
              </button>
            </div>
          </div>
          <div className="vben-card-body">
            <p className="mb-3 text-sm text-slate-600 dark:text-slate-300">
              直接按住画面中的滑块向右拖动到缺口位置（拖动实时同步到真实浏览器）。
              {submitting ? '正在判定结果…' : dragging ? '拖动中…' : '请开始拖动。'}
            </p>
            {frameError ? (
              <div className="flex items-center gap-2 text-sm text-red-600 dark:text-red-400">
                <Info className="w-4 h-4" />
                {frameError}
              </div>
            ) : frame ? (
              <div className="border border-slate-200 dark:border-slate-700 rounded-lg overflow-hidden bg-slate-100 dark:bg-slate-900">
                <img
                  ref={imgRef}
                  src={frameSrc}
                  alt="滑块验证页面（实时）"
                  draggable={false}
                  onMouseDown={handleMouseDown}
                  className={`max-w-full h-auto select-none ${dragging ? 'cursor-grabbing' : 'cursor-grab'}`}
                />
              </div>
            ) : (
              <div className="flex items-center justify-center py-16 text-slate-400 dark:text-slate-500">
                <Loader2 className="w-6 h-6 animate-spin mr-2" />
                正在加载实时画面…
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
