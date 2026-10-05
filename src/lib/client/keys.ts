import { apiRequest } from './http';
import type { ServiceId } from '@/lib/services';
import type { ApiKeysOverview, ApiKeyStatus } from '@/types/account';

export function fetchApiKeys(): Promise<ApiKeysOverview> {
  return apiRequest<ApiKeysOverview>('/api/keys', { cache: 'no-store' });
}

export function saveApiKey(service: ServiceId, key: string): Promise<ApiKeyStatus> {
  return apiRequest<ApiKeyStatus>(`/api/keys/${service}`, { method: 'PUT', body: JSON.stringify({ key }) });
}

export function deleteApiKey(service: ServiceId): Promise<ApiKeyStatus> {
  return apiRequest<ApiKeyStatus>(`/api/keys/${service}`, { method: 'DELETE' });
}
