/**
 * authStore refresh 関連テスト
 *
 * - single-flight: 複数の concurrent refreshAccessToken 呼び出しが 1 回の API コールに集約される
 * - Cookie フォールバック: tokens がメモリに無い場合でも refreshToken(undefined) で呼べる
 * - proactive refresh: login 後にタイマーが設定される
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// authApi を mock
vi.mock('@/lib/api/auth', () => ({
  authApi: {
    login: vi.fn(),
    register: vi.fn(),
    logout: vi.fn(),
    refreshToken: vi.fn(),
    switchTenant: vi.fn(),
  },
}));

// userProfile API を mock
vi.mock('@/lib/api/userProfile', () => ({
  getUserProfile: vi.fn().mockResolvedValue({
    userId: 'u1',
    username: 'test',
    email: 'test@example.com',
    displayName: 'Test',
    isActive: true,
    emailVerified: true,
  }),
  getUserTenants: vi.fn().mockResolvedValue([]),
  getUserLicenses: vi.fn().mockResolvedValue([]),
}));

// router.config の clearAuthLoaderCache mock
vi.mock('@/app/router.config', () => ({
  clearAuthLoaderCache: vi.fn(),
}));

// miraStore mock
vi.mock('@/stores/miraStore', () => ({
  useMiraStore: {
    persist: { clearStorage: vi.fn() },
    setState: vi.fn(),
  },
}));

import { useAuthStore, _resetRefreshPromise, cancelProactiveRefresh } from '../authStore';
import { authApi } from '@/lib/api/auth';

describe('authStore - refresh token mechanics', () => {
  beforeEach(() => {
    // store をリセット
    useAuthStore.setState({
      user: null,
      currentTenant: null,
      tokens: null,
      tenants: [],
      licenses: [],
      isAuthenticated: false,
      otpState: null,
    });
    _resetRefreshPromise();
    cancelProactiveRefresh();
    vi.clearAllMocks();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    cancelProactiveRefresh();
  });

  describe('single-flight guard', () => {
    it('concurrent refreshAccessToken calls should result in only one API call', async () => {
      // メモリにトークンをセット
      useAuthStore.setState({
        tokens: { accessToken: 'old-at', refreshToken: 'old-rt', expiresIn: 3600 },
        isAuthenticated: true,
      });

      // refreshToken API に少し遅延を入れる
      let resolveRefresh!: (value: any) => void;
      const refreshPromise = new Promise((resolve) => {
        resolveRefresh = resolve;
      });
      vi.mocked(authApi.refreshToken).mockReturnValue(refreshPromise as any);

      // 3 つの concurrent refresh を発火
      const { refreshAccessToken } = useAuthStore.getState();
      const p1 = refreshAccessToken();
      const p2 = refreshAccessToken();
      const p3 = refreshAccessToken();

      // API はまだ 1 回だけ呼ばれている
      expect(authApi.refreshToken).toHaveBeenCalledTimes(1);
      expect(authApi.refreshToken).toHaveBeenCalledWith('old-rt');

      // resolve
      resolveRefresh({ accessToken: 'new-at', refreshToken: 'new-rt', expiresIn: 3600 });

      const [r1, r2, r3] = await Promise.all([p1, p2, p3]);

      // 全て同じ結果
      expect(r1).toBe(true);
      expect(r2).toBe(true);
      expect(r3).toBe(true);

      // API は依然 1 回だけ
      expect(authApi.refreshToken).toHaveBeenCalledTimes(1);

      // store のトークンが更新されている
      expect(useAuthStore.getState().tokens?.accessToken).toBe('new-at');
      expect(useAuthStore.getState().tokens?.refreshToken).toBe('new-rt');
    });

    it('after first refresh completes, a new call should make a new API call', async () => {
      useAuthStore.setState({
        tokens: { accessToken: 'at1', refreshToken: 'rt1', expiresIn: 3600 },
        isAuthenticated: true,
      });

      vi.mocked(authApi.refreshToken)
        .mockResolvedValueOnce({ accessToken: 'at2', refreshToken: 'rt2', expiresIn: 3600 })
        .mockResolvedValueOnce({ accessToken: 'at3', refreshToken: 'rt3', expiresIn: 3600 });

      // 1st refresh
      const result1 = await useAuthStore.getState().refreshAccessToken();
      expect(result1).toBe(true);
      expect(authApi.refreshToken).toHaveBeenCalledTimes(1);

      // 2nd refresh (should be a new call)
      const result2 = await useAuthStore.getState().refreshAccessToken();
      expect(result2).toBe(true);
      expect(authApi.refreshToken).toHaveBeenCalledTimes(2);
    });
  });

  describe('Cookie fallback (no memory token)', () => {
    it('should call refreshToken with undefined when tokens are null (Cookie fallback)', async () => {
      // tokens = null → F5 / 新タブを模擬
      useAuthStore.setState({
        tokens: null,
        isAuthenticated: true,
      });

      vi.mocked(authApi.refreshToken).mockResolvedValue({
        accessToken: 'cookie-at',
        refreshToken: 'cookie-rt',
        expiresIn: 3600,
      });

      const result = await useAuthStore.getState().refreshAccessToken();

      expect(result).toBe(true);
      // refreshToken(undefined) → バックエンドが Cookie から読む
      expect(authApi.refreshToken).toHaveBeenCalledWith(undefined);
      expect(useAuthStore.getState().tokens?.accessToken).toBe('cookie-at');
    });
  });

  describe('proactive refresh', () => {
    it('should schedule proactive refresh timer after successful refresh', async () => {
      useAuthStore.setState({
        tokens: { accessToken: 'at', refreshToken: 'rt', expiresIn: 3600 },
        isAuthenticated: true,
      });

      vi.mocked(authApi.refreshToken).mockResolvedValue({
        accessToken: 'new-at',
        refreshToken: 'new-rt',
        expiresIn: 3600, // 1 hour
      });

      // refresh 前はタイマーなし
      expect(vi.getTimerCount()).toBe(0);

      // refresh
      await useAuthStore.getState().refreshAccessToken();
      expect(authApi.refreshToken).toHaveBeenCalledTimes(1);

      // proactive refresh タイマーが設定されている
      expect(vi.getTimerCount()).toBe(1);
    });

    it('should not fire proactive refresh after logout', async () => {
      useAuthStore.setState({
        tokens: { accessToken: 'at', refreshToken: 'rt', expiresIn: 3600 },
        isAuthenticated: true,
      });

      vi.mocked(authApi.refreshToken).mockResolvedValue({
        accessToken: 'new-at',
        refreshToken: 'new-rt',
        expiresIn: 600, // 10 min → proactive at (600-120)=480s
      });

      await useAuthStore.getState().refreshAccessToken();

      // logout → cancelProactiveRefresh が呼ばれる
      cancelProactiveRefresh();
      useAuthStore.setState({ isAuthenticated: false, tokens: null });

      // タイマーを進めても API は再呼び出しされない
      vi.advanceTimersByTime(600 * 1000);
      await vi.runAllTimersAsync();

      // refresh は最初の 1 回のみ
      expect(authApi.refreshToken).toHaveBeenCalledTimes(1);
    });
  });

  describe('refresh failure', () => {
    it('should return false on API error', async () => {
      useAuthStore.setState({
        tokens: { accessToken: 'at', refreshToken: 'rt', expiresIn: 3600 },
        isAuthenticated: true,
      });

      vi.mocked(authApi.refreshToken).mockRejectedValue(new Error('401'));

      const result = await useAuthStore.getState().refreshAccessToken();
      expect(result).toBe(false);
    });
  });
});
