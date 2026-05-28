/**
 * Authentication API
 */

import { apiClient, getApiErrors } from './client';
import type { UserProfile } from './userProfile';

export interface LoginRequest {
  usernameOrEmail: string;
  password: string;
  tenantId?: string;
  rememberMe?: boolean;
}

export interface SignupRequest {
  username: string;
  email: string;
  password: string;
  displayName: string;
  firstName?: string;
  lastName?: string;
}

export interface TokenDto {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface TenantContextDto {
  tenantId: string;
  tenantName: string;
  displayName: string;
}

export interface AuthenticationResponse {
  user: UserProfile;
  tokens: TokenDto;
  currentTenant: TenantContextDto;
}

export interface RefreshTokenRequest {
  refreshToken: string;
}

export interface SwitchTenantRequest {
  tenantId: string;
}

export const authApi = {
  /**
   * Login with username/email and password
   */
  async login(request: LoginRequest): Promise<AuthenticationResponse> {
    try {
      const response = await apiClient.post<AuthenticationResponse>(
        '/auth/login',
        request
      );

      return response.data;
    } catch (error) {
      const errors = getApiErrors(error);
      throw new Error(errors.join(', '));
    }
  },

  /**
   * Register a new user
   */
  async register(request: SignupRequest): Promise<AuthenticationResponse> {
    try {
      const response = await apiClient.post<AuthenticationResponse>(
        '/auth/signup',
        request
      );

      return response.data;
    } catch (error) {
      const errors = getApiErrors(error);
      throw new Error(errors.join(', '));
    }
  },

  /**
   * Logout
   */
  async logout(refreshToken?: string): Promise<void> {
    try {
      // If no refresh token is provided, we just clear local state (handled by caller)
      // But if we have one, we should notify backend to invalidate it
      if (refreshToken) {
        await apiClient.post<void>('/auth/logout', { refreshToken });
      }
    } catch (error) {
      // Ignore logout errors (best effort)
      console.warn('Logout API call failed', error);
    }
  },

  /**
   * Refresh access token.
   * refreshToken が指定された場合は body に載せる。
   * 未指定の場合は空 body で POST し、バックエンドが Cookie から refreshToken を読む。
   */
  async refreshToken(refreshToken?: string): Promise<TokenDto> {
    try {
      const body = refreshToken ? { refreshToken } : {};
      const response = await apiClient.post<AuthenticationResponse>(
        '/auth/refresh',
        body,
        {
          headers: {
            // refresh 自体が 401 リトライ対象にならないよう抑制
            'X-Mirel-Skip-Auth-Redirect': 'true',
          },
        }
      );

      return response.data.tokens;
    } catch (error) {
      const errors = getApiErrors(error);
      throw new Error(errors.join(', '));
    }
  },

  /**
   * Switch tenant
   */
  async switchTenant(tenantId: string): Promise<AuthenticationResponse> {
    try {
      const response = await apiClient.post<AuthenticationResponse>(
        '/auth/switch-tenant',
        { tenantId },
        {
          headers: {
            'X-Tenant-ID': tenantId,
          },
        }
      );

      return response.data;
    } catch (error) {
      const errors = getApiErrors(error);
      throw new Error(errors.join(', '));
    }
  },
};
