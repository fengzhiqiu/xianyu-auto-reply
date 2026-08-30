/**
 * 人工滑块验证页面（2A）
 *
 * 功能：
 * 1. 展示「待人工验证」列表（自动过滑块失败后由 websocket 侧登记）。
 * 2. 管理员点击「处理」→ 创建浏览器会话并现取新鲜滑块链接。
 * 3. 轮询截图展示滑块页面，管理员真实拖动滑块，轨迹被采样并回放给浏览器。
 * 4. 通过后由后端写回 x5* Cookie 并重启账号；可随时放弃或关闭。
 */
import { useCallback, useEffect, useRef, useState, type MouseEvent as ReactMouseEvent } from 'react'
import { Loader2, RefreshCw, Info, ShieldAlert, X } from 'lucide-react'
import { useAuthStore } from '@/store/authStore'
import { useUIStore } from '@/store/uiStore'
import { useManualCaptchaStore } from '@/store/manualCaptchaStore'
import { PageLoading } from '@/components/common/Loading'
import { getApiErrorMessage } from '@/utils/request'
import {
  getManualCaptchaPending,
  prepareManualCaptcha,
  getManualCaptchaFrame,
  dragManualCaptcha,
  closeManualCaptcha,
  dismissManualCaptcha,
  getManualFallbackConfig,
  updateManualFallbackConfig,
  type ManualCaptchaPendingItem,
  type ManualCaptchaFrame,
} from '@/api/admin'

interface TrackPoint {
  x: number
  y: number
  t: number
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
  const [dragging, setDragging] = useState(false)
  const [submitting, setSubmitting] = useState(false)

  // 人工滑块兜底开关
  const [fallbackEnabled, setFallbackEnabled] = useState(false)
  const [configLoading, setConfigLoading] = useState(true)
  const [savingConfig, setSavingConfig] = useState(false)

  // 拖动轨迹采样相关 ref
  const imgRef = useRef<HTMLImageElement | null>(null)
  const trackRef = useRef<TrackPoint[]>([])
  const startTimeRef = useRef(0)
  const draggingRef = useRef(false)
  const submittingRef = useRef(false)

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

  const fetchFrame = useCallback(async (sid: string) => {
    try {
      const res = await getManualCaptchaFrame(sid)
      if (res.success && res.data) {
        setFrame(res.data)
        setFrameError('')
      } else {
        setFrameError(res.message || '截图失败')
      }
    } catch (error) {
      setFrameError(getApiErrorMessage(error, '截图失败'))
    }
  }, [])

  // 轮询截图（拖动与提交期间暂停，避免图片被替换打断操作）
  useEffect(() => {
    if (!sessionId) return
    const timer = setInterval(() => {
      if (draggingRef.current || submittingRef.current) return
      void fetchFrame(sessionId)
    }, 500)
    return () => clearInterval(timer)
  }, [sessionId, fetchFrame])

  const closeSession = useCallback(async () => {
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
    trackRef.current = []
  }, [sessionId])

  // 页面卸载时关闭会话
  useEffect(() => {
    return () => {
      if (sessionId) {
        void closeManualCaptcha(sessionId)
      }
    }
  }, [sessionId])

  const handleSolve = async (item: ManualCaptchaPendingItem) => {
    setPreparing(true)
    try {
      const res = await prepareManualCaptcha(item.account_id)
      if (res.success && res.data?.session_id) {
        setActiveItem(item)
        setSessionId(res.data.session_id)
        setFrame(null)
        setFrameError('')
        await fetchFrame(res.data.session_id)
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

  const submitDrag = async () => {
    if (!sessionId || !activeItem) return
    if (trackRef.current.length < 2) return
    submittingRef.current = true
    setSubmitting(true)
    try {
      const res = await dragManualCaptcha(
        sessionId,
        trackRef.current,
        activeItem.account_id,
        activeItem.id,
      )
      if (res.success && res.data?.passed) {
        addToast({
          type: 'success',
          message: res.data.cookie_message || '验证通过，Cookie 已写回并重启账号',
        })
        await closeSession()
        loadPending()
        void refreshPendingCount()
      } else {
        addToast({
          type: 'warning',
          message: res.message || res.data?.cookie_message || '验证未通过，请重试',
        })
        // 立即刷新一帧，展示滑块重试状态
        await fetchFrame(sessionId)
      }
    } catch (error) {
      addToast({ type: 'error', message: getApiErrorMessage(error, '回放轨迹失败') })
    } finally {
      submittingRef.current = false
      setSubmitting(false)
      trackRef.current = []
    }
  }

  // ---- 拖动采样 ----
  const getNaturalPoint = (e: MouseEvent): TrackPoint | null => {
    const img = imgRef.current
    if (!img || !img.naturalWidth || !img.naturalHeight) return null
    const rect = img.getBoundingClientRect()
    if (rect.width <= 0 || rect.height <= 0) return null
    const x = ((e.clientX - rect.left) / rect.width) * img.naturalWidth
    const y = ((e.clientY - rect.top) / rect.height) * img.naturalHeight
    return { x: Math.round(x), y: Math.round(y), t: 0 }
  }

  const handleMouseDown = (e: ReactMouseEvent<HTMLImageElement>) => {
    if (submittingRef.current) return
    const p = getNaturalPoint(e.nativeEvent)
    if (!p) return
    e.preventDefault()
    startTimeRef.current = performance.now()
    trackRef.current = [{ x: p.x, y: p.y, t: 0 }]
    draggingRef.current = true
    setDragging(true)
    window.addEventListener('mousemove', handleWindowMouseMove)
    window.addEventListener('mouseup', handleWindowMouseUp)
  }

  const handleWindowMouseMove = (e: MouseEvent) => {
    const p = getNaturalPoint(e)
    if (!p) return
    trackRef.current.push({ x: p.x, y: p.y, t: Math.round(performance.now() - startTimeRef.current) })
  }

  const handleWindowMouseUp = (e: MouseEvent) => {
    window.removeEventListener('mousemove', handleWindowMouseMove)
    window.removeEventListener('mouseup', handleWindowMouseUp)
    const p = getNaturalPoint(e)
    if (p) {
      trackRef.current.push({ x: p.x, y: p.y, t: Math.round(performance.now() - startTimeRef.current) })
    }
    draggingRef.current = false
    setDragging(false)
    if (trackRef.current.length >= 2) {
      void submitDrag()
    } else {
      trackRef.current = []
    }
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
          <p className="page-description">自动过滑块失败后，在此手动完成滑块验证</p>
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
            开启「人工滑块兜底」后，账号自动过滑块失败会在此登记待处理记录。点击「处理」会打开真实浏览器滑块页面，拖动图片中的滑块即可完成验证；通过后 Cookie 会自动写回并重启账号。
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
              <button onClick={() => { void closeSession(); loadPending() }} className="btn-ios-secondary">
                <X className="w-4 h-4" />
                关闭会话
              </button>
            </div>
          </div>
          <div className="vben-card-body">
            <p className="mb-3 text-sm text-slate-600 dark:text-slate-300">
              按住图片中的滑块向右拖动到缺口位置（轨迹会实时采样并回放给浏览器）。
              {submitting ? '正在判定结果…' : dragging ? '拖动中…' : '请开始拖动。'}
            </p>
            {frameError ? (
              <div className="flex items-center gap-2 text-sm text-red-600 dark:text-red-400">
                <Info className="w-4 h-4" />
                {frameError}
                <button onClick={() => sessionId && fetchFrame(sessionId)} className="underline">重试</button>
              </div>
            ) : frame ? (
              <div className="border border-slate-200 dark:border-slate-700 rounded-lg overflow-hidden bg-slate-100 dark:bg-slate-900">
                <img
                  ref={imgRef}
                  src={frameSrc}
                  alt="滑块验证页面"
                  draggable={false}
                  onMouseDown={handleMouseDown}
                  className={`max-w-full h-auto select-none ${dragging ? 'cursor-grabbing' : 'cursor-grab'}`}
                />
              </div>
            ) : (
              <div className="flex items-center justify-center py-16 text-slate-400 dark:text-slate-500">
                <Loader2 className="w-6 h-6 animate-spin mr-2" />
                正在加载截图…
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
