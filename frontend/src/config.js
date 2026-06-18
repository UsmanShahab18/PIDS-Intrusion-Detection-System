// API Configuration - Works on ANY device on the network
const getApiBase = () => {
  // Use the same hostname that the browser is using
  // This automatically works for localhost AND network IPs
  const hostname = window.location.hostname;
  return `http://${hostname}:8000/api`;
};

export const API_BASE = getApiBase();