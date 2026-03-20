import axios from 'axios';

const GATEWAY_URL = import.meta.env.VITE_GATEWAY_URL || '';
const GOVERNANCE_URL = import.meta.env.VITE_GOVERNANCE_URL || '';

export const gateway = axios.create({ baseURL: GATEWAY_URL, timeout: 10000 });
export const governance = axios.create({ baseURL: GOVERNANCE_URL, timeout: 10000 });

function attachAuth(instance: typeof gateway) {
  instance.interceptors.request.use((config) => {
    const token = localStorage.getItem('btv_token');
    if (token) config.headers.Authorization = `Bearer ${token}`;
    const apiKey = localStorage.getItem('btv_api_key');
    if (apiKey) config.headers['X-API-Key'] = apiKey;
    return config;
  });
  instance.interceptors.response.use(undefined, (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('btv_token');
      window.location.href = '/login';
    }
    return Promise.reject(err);
  });
}

attachAuth(gateway);
attachAuth(governance);
