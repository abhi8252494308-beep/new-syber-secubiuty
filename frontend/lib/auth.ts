// Authentication has been removed - this file is kept for compatibility
// All pages are now publicly accessible

export const setAuthTokens = (_accessToken: string, _refreshToken: string) => {
  // No-op
};

export const getAccessToken = () => {
  return null;
};

export const getRefreshToken = () => {
  return null;
};

export const removeAuthTokens = () => {
  // No-op
};

export const isAuthenticated = () => {
  return true;
};