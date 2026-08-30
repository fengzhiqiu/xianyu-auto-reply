import { create } from 'zustand'
import { getManualCaptchaPending } from '@/api/admin'

interface ManualCaptchaState {
  pendingCount: number
  setPendingCount: (count: number) => void
  refreshPendingCount: () => Promise<void>
}

export const useManualCaptchaStore = create<ManualCaptchaState>((set) => ({
  pendingCount: 0,
  setPendingCount: (count) => set({ pendingCount: count }),
  refreshPendingCount: async () => {
    try {
      const res = await getManualCaptchaPending()
      if (res.success) {
        set({ pendingCount: (res.data || []).length })
      }
    } catch {
      // 拉取失败静默忽略，避免影响主界面
    }
  },
}))
