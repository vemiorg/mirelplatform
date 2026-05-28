import { create } from 'zustand';
import type { OtpPurpose } from '@/lib/api/otp.types';
import { authApi, type LoginRequest, type SignupRequest, type TokenDto, type TenantContextDto } from '@/lib/api/auth';
import { getUserProfile, getUserTenants, getUserLicenses, type UserProfile, type TenantInfo, type LicenseInfo } from '@/lib/api/userProfile';

// ── Single-flight guard ──
// 複数の 401 応答が同時に refreshAccessToken を呼んでも、実際の refresh は 1 回だけ実行される。
let _refreshPromise: Promise<boolean> | null = null;

// ── Proactive refresh timer ──
let _proactiveRefreshTimer: ReturnType<typeof setTimeout> | null = null;

/** proactive refresh のバッファ秒数（期限の何秒前に更新するか） */
const PROACTIVE_REFRESH_BUFFER_SEC = 120; // 2分前

/**
 * OTP認証状態
 */
interface OtpState {
  email: string | null;
  purpose: OtpPurpose | null;
  requestId: string | null;
  expiresAt: Date | null;
  expirationMinutes: number | null;
  resendCooldownSeconds: number | null;
}

interface AuthState {
  user: UserProfile | null;
  currentTenant: TenantContextDto | null;
  tokens: TokenDto | null;
  tenants: TenantInfo[];
  licenses: LicenseInfo[];
  isAuthenticated: boolean;
  
  // OTP認証状態
  otpState: OtpState | null;

  // Actions
  login: (data: LoginRequest) => Promise<void>;
  signup: (data: SignupRequest) => Promise<void>;
  logout: () => Promise<void>;
  switchTenant: (tenantId: string) => Promise<void>;
  fetchProfile: () => Promise<void>;
  rehydrateFromServerSession: () => Promise<void>;
  
  setAuth: (user: UserProfile, tenant: TenantContextDto | null, tokens: TokenDto) => void;
  clearAuth: () => void;
  refreshAccessToken: () => Promise<boolean>;
  updateUser: (updatedUser: Partial<UserProfile>) => void;
  
  // OTP Actions
  setOtpState: (email: string, purpose: OtpPurpose, requestId: string, expirationMinutes: number, resendCooldownSeconds?: number) => void;
  clearOtpState: () => void;
  isOtpExpired: () => boolean;
}

export const useAuthStore = create<AuthState>()((set, get) => ({
  user: null,
  currentTenant: null,
  tokens: null,
  tenants: [],
  licenses: [],
  isAuthenticated: false,
  otpState: null,

      login: async (request: LoginRequest) => {
        // セキュリティのため、ログイン時に機密性の高いローカルストレージをクリア
        // (以前のユーザーのデータが残存するのを防ぐ)
        clearClientStorage();

        const response = await authApi.login(request);
        set({
          user: response.user,
          currentTenant: response.currentTenant,
          tokens: response.tokens,
          isAuthenticated: true,
        });
        // Proactive refresh タイマー起動
        if (response.tokens?.expiresIn) {
          scheduleProactiveRefresh(response.tokens.expiresIn);
        }
        // Login successful, fetch full profile data
        await get().fetchProfile();
      },

      signup: async (request: SignupRequest) => {
        // セキュリティのため、サインアップ時にもローカルストレージをクリア
        clearClientStorage();

        const response = await authApi.register(request);
        set({
          user: response.user,
          currentTenant: response.currentTenant,
          tokens: response.tokens,
          isAuthenticated: true,
        });
        // Proactive refresh タイマー起動
        if (response.tokens?.expiresIn) {
          scheduleProactiveRefresh(response.tokens.expiresIn);
        }
        await get().fetchProfile();
      },

      logout: async () => {
        console.log('[DEBUG logout] Step 1: Starting logout...');
        // Proactive refresh タイマーをキャンセル
        cancelProactiveRefresh();
        const { tokens } = get();
        
        console.log('[DEBUG logout] Step 2: Calling logout API (awaiting)...');
        // 1. バックエンドへログアウト通知(同期的に待つ)
        try {
          await authApi.logout(tokens?.refreshToken);
        } catch (error) {
          console.warn('Logout API call failed', error);
        }
        
        // 2. authLoaderのキャッシュをクリア (重要: Cookie削除後の再アクセス時に必ずサーバー検証を実行)
        console.log('[DEBUG logout] Step 2.5: Clearing authLoader cache...');
        try {
          const { clearAuthLoaderCache } = await import('@/app/router.config');
          clearAuthLoaderCache();
        } catch (error) {
          console.warn('Failed to clear authLoader cache', error);
        }

        // Miraの会話履歴をクリア（ローカルストレージ）
        console.log('[DEBUG logout] Step 2.6: Clearing Mira store persistence...');
        try {
          // useMiraStoreを動的インポート（循環参照回避のため）
          const { useMiraStore } = await import('@/stores/miraStore');
          useMiraStore.persist.clearStorage();
          
          // メモリストアもリセット（念のため）
          // useMiraStore.setState({ conversations: {}, activeConversationId: null });
        } catch (error) {
          console.warn('Failed to clear Mira store persistence', error);
        }
        
        console.log('[DEBUG logout] Step 3: Redirecting to /login (immediate)...');
        // 3. ログイン画面へリダイレクト(履歴を残さない)
        // 即座にリダイレクトすることで、React の再レンダリングを防止
        window.location.replace('/login');
        
        // この後の処理は実行されない（ページ遷移するため）
        // state clear は次回ページ読み込み時に自動的にクリアされる（メモリ内のみ）
      },

      switchTenant: async (tenantId: string) => {
        const response = await authApi.switchTenant(tenantId);
        set({
          user: response.user,
          currentTenant: response.currentTenant,
          tokens: response.tokens,
        });
        
        // テナント切り替え後は権限（ロール）が変わる可能性があるため、
        // ナビゲーションやアクセス権を確実に再評価するために画面をリロード
        // authLoaderのキャッシュをクリアして、次回読み込み時に最新状態を取得
        try {
          const { clearAuthLoaderCache } = await import('@/app/router.config');
          clearAuthLoaderCache();
        } catch (error) {
          console.warn('Failed to clear authLoader cache', error);
        }
        
        // 現在のページをリロードして権限を再評価
        window.location.reload();
      },

      fetchProfile: async () => {
        try {
          const [user, tenants, licenses] = await Promise.all([
            getUserProfile(),
            getUserTenants(),
            getUserLicenses()
          ]);
          set({ user, tenants, licenses });
        } catch (error) {
          console.error('Failed to fetch profile data', error);
          // If profile fetch fails (e.g. 401), we might want to logout or handle it
        }
      },

      // HttpOnly Cookie ベースのセッションからストアを再構築
      // F5 や新規タブなどでメモリストアが空になった場合に使用
      rehydrateFromServerSession: async () => {
        try {
          // authLoader からの呼び出し時は、グローバルな 401 リダイレクトを抑制する
          // (authLoader 側で適切に returnUrl 付きでリダイレクトするため)
          const config = {
            headers: {
              'X-Mirel-Skip-Auth-Redirect': 'true'
            }
          };

          const [user, tenants, licenses] = await Promise.all([
            getUserProfile(config),
            getUserTenants(config),
            getUserLicenses(config),
          ]);

          set({
            user,
            currentTenant: user.currentTenant ?? null,
            tenants,
            licenses,
            // HttpOnly Cookie 経由で /users/me が成功している時点で認証済み
            isAuthenticated: true,
          });

          // rehydrate 成功 → proactive refresh をスケジュール
          // access token の正確な残り時間は不明（Cookie HttpOnly）なので、
          // tokens がメモリにあれば expiresIn を使い、なければ早めに refresh を試みる
          const tokens = get().tokens;
          if (tokens?.expiresIn) {
            scheduleProactiveRefresh(tokens.expiresIn);
          } else {
            // Cookie から復元した場合、access token の残り時間が不明。
            // 安全のため 5 分後に proactive refresh を試みる。
            scheduleProactiveRefresh(300);
          }
        } catch (error) {
          console.error('Failed to rehydrate auth store from server session', error);
          // 401 などの場合は呼び出し側 (authLoader) でリダイレクト制御を行う
          throw error;
        }
      },

      setAuth: (user, tenant, tokens) => {
        set({ user, currentTenant: tenant, tokens, isAuthenticated: true });
      },

      clearAuth: () => {
        set({ 
          user: null, 
          currentTenant: null, 
          tokens: null, 
          tenants: [],
          licenses: [],
          isAuthenticated: false 
        });
      },

      /**
       * リフレッシュトークンを使用してアクセストークンを更新（single-flight）
       *
       * - 同時に複数呼ばれても実際の API コールは 1 回だけ（single-flight ガード）
       * - メモリに refreshToken があれば body に載せる
       * - メモリに無い場合（F5/新タブ）は空 body で POST → バックエンドが Cookie から読む
       * - 成功後に proactive refresh タイマーを再スケジュール
       *
       * @returns 更新成功時 true、失敗時 false
       */
      refreshAccessToken: async () => {
        // single-flight: 進行中の refresh があればそれを待つ
        if (_refreshPromise) {
          console.log('[Auth] Refresh already in flight, waiting...');
          return _refreshPromise;
        }

        _refreshPromise = (async () => {
          try {
            const { tokens } = get();
            // メモリに refreshToken があれば使う、なければ Cookie にフォールバック（body 空）
            const refreshTokenValue = tokens?.refreshToken;

            console.log('[Auth] Refreshing access token...', {
              hasMemoryToken: !!refreshTokenValue,
              fallbackToCookie: !refreshTokenValue,
            });

            const response = await authApi.refreshToken(refreshTokenValue);

            // rotation 後の新トークンをストアに反映
            set({ tokens: response });

            // proactive refresh タイマーを再スケジュール
            scheduleProactiveRefresh(response.expiresIn);

            console.log('[Auth] Access token refreshed successfully (rotation applied)');
            return true;
          } catch (error) {
            console.error('[Auth] Failed to refresh access token', error);
            return false;
          } finally {
            _refreshPromise = null;
          }
        })();

        return _refreshPromise;
      },

      updateUser: (updatedUser: Partial<UserProfile>) => {
        const { user } = get();
        if (!user) return;
        set({ user: { ...user, ...updatedUser } });
      },
      
      setOtpState: (email: string, purpose: OtpPurpose, requestId: string, expirationMinutes: number, resendCooldownSeconds?: number) => {
        const expiresAt = new Date();
        expiresAt.setMinutes(expiresAt.getMinutes() + expirationMinutes);
        
        set({
          otpState: {
            email,
            purpose,
            requestId,
            expiresAt,
            expirationMinutes,
            resendCooldownSeconds: resendCooldownSeconds ?? null,
          },
        });
      },
      
      clearOtpState: () => {
        set({ otpState: null });
      },
      
      isOtpExpired: () => {
        const { otpState } = get();
        if (!otpState || !otpState.expiresAt) return true;
        return new Date() > new Date(otpState.expiresAt);
      },
    })
);

/**
 * Proactive refresh: access token の有効期限の数分前にバックグラウンドで refresh を実行。
 * これにより「リクエスト失敗 → 401 → リトライ」のラグを回避する。
 *
 * @param expiresInSec access token の残り有効期限（秒）
 */
function scheduleProactiveRefresh(expiresInSec: number) {
  // 既存タイマーをクリア
  if (_proactiveRefreshTimer) {
    clearTimeout(_proactiveRefreshTimer);
    _proactiveRefreshTimer = null;
  }

  // バッファを引いた時間後にリフレッシュ実行
  const delaySec = Math.max(expiresInSec - PROACTIVE_REFRESH_BUFFER_SEC, 10);
  console.log(`[Auth] Proactive refresh scheduled in ${delaySec}s (token expires in ${expiresInSec}s)`);

  _proactiveRefreshTimer = setTimeout(async () => {
    console.log('[Auth] Proactive refresh firing...');
    const { refreshAccessToken, isAuthenticated } = useAuthStore.getState();
    if (!isAuthenticated) {
      console.log('[Auth] Not authenticated, skipping proactive refresh');
      return;
    }
    const success = await refreshAccessToken();
    if (!success) {
      console.warn('[Auth] Proactive refresh failed — user may be logged out on next API call');
    }
  }, delaySec * 1000);
}

/** Cancel the proactive refresh timer (on logout). Exported for testing. */
export function cancelProactiveRefresh() {
  if (_proactiveRefreshTimer) {
    clearTimeout(_proactiveRefreshTimer);
    _proactiveRefreshTimer = null;
  }
}

/** Reset the single-flight guard (for testing only). */
export function _resetRefreshPromise() {
  _refreshPromise = null;
}

/**
 * 機密性の高いローカルストレージデータをクリアするヘルパー
 * 
 * ログアウト時だけでなく、ログイン/サインアップ時にも実行することで、
 * 共有端末などでのデータ残留リスク（Session Fixationの一種）を防ぐ。
 * 
 * 注意: MiraStoreは永続化されているが、サーバー同期されるためクリアしても復元可能。
 */
const clearClientStorage = () => {
  try {
    console.log('[Auth] Clearing sensitive client storage...');
    
    // 1. Mira(AIチャット)の永続化ストアをクリア
    // Zustand persist middleware のキー
    localStorage.removeItem('mira-store');
    
    // 2. Mira入力履歴をクリア
    localStorage.removeItem('mira-input-history');
    
    console.log('[Auth] Client storage cleared successfully');
  } catch (error) {
    console.warn('[Auth] Failed to clear client storage', error);
  }
};

