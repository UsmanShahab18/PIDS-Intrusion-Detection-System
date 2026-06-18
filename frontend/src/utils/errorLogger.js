import { API_BASE } from '../config';

class ErrorLogger {
  static isInitialized = false;
  static _isSending = false;        // Re-entrancy guard - prevents infinite loop
  static _recentErrors = new Map();  // Deduplication cache
  static _DEDUP_WINDOW_MS = 5000;   // Same error ignored within 5 seconds

  static async logError(error, source = 'frontend', details = {}) {
    // --- GUARD: If we're already inside a logError call, bail out ---
    // This prevents the infinite loop where logging a network error
    // triggers another network error which triggers another log...
    if (this._isSending) return null;

    const errorMessage = error.message || String(error);

    // --- GUARD: Skip errors caused by the error logger itself ---
    if (errorMessage.includes('/errors/log/') ||
        errorMessage.includes('Failed to fetch errors') ||
        errorMessage.includes('WebSocket') ||
        errorMessage.includes('isTrusted')) {
      return null;
    }

    // --- GUARD: Deduplicate - don't report the same error repeatedly ---
    const errorKey = `${error.name}:${errorMessage.slice(0, 100)}`;
    const now = Date.now();
    if (this._recentErrors.has(errorKey)) {
      const lastTime = this._recentErrors.get(errorKey);
      if (now - lastTime < this._DEDUP_WINDOW_MS) return null;
    }
    this._recentErrors.set(errorKey, now);

    // Clean old entries every 50 items
    if (this._recentErrors.size > 50) {
      for (const [key, time] of this._recentErrors) {
        if (now - time > this._DEDUP_WINDOW_MS) this._recentErrors.delete(key);
      }
    }

    const errorData = {
      type: error.name || 'Error',
      message: errorMessage,
      source: source,
      details: {
        ...details,
        url: window.location.href,
        timestamp: new Date().toISOString()
      },
      file_path: this.extractFilePath(error.stack),
      line_number: this.extractLineNumber(error.stack)
    };

    // Log to console (only once, not spammed)
    console.log('[PIDS Error Logger]', errorData);

    // Send to backend with re-entrancy protection
    this._isSending = true;
    try {
      await fetch(`${API_BASE}/errors/log/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(errorData)
      });
    } catch (e) {
      // Silently fail - do NOT log this failure (that would cause the loop)
    } finally {
      this._isSending = false;
    }

    return errorData;
  }

  static extractFilePath(stack) {
    if (!stack) return null;
    const match = stack.match(/at\s+.*\s+\(?(.*?):\d+:\d+\)?/);
    return match ? match[1] : null;
  }

  static extractLineNumber(stack) {
    if (!stack) return null;
    const match = stack.match(/:(\d+):\d+/);
    return match ? parseInt(match[1]) : null;
  }

  static init() {
    if (this.isInitialized) return;
    this.isInitialized = true;

    // Catch unhandled errors
    window.onerror = (message, source, lineno, colno, error) => {
      this.logError(error || new Error(message), 'frontend', {
        source: source,
        line: lineno,
        column: colno
      });
      return false;
    };

    // Catch unhandled promise rejections
    window.onunhandledrejection = (event) => {
      const error = event.reason instanceof Error 
        ? event.reason 
        : new Error(String(event.reason));
      
      // Skip network errors from Axios / fetch - these are usually just
      // the backend being briefly unavailable and not real app bugs
      const msg = error.message || '';
      if (msg.includes('Network Error') || msg.includes('Failed to fetch') ||
          msg.includes('WebSocket') || msg.includes('isTrusted')) {
        return;
      }
      
      this.logError(error, 'frontend', { type: 'UnhandledPromiseRejection' });
    };

    // Intercept console.error
    const originalConsoleError = console.error;
    console.error = (...args) => {
      const message = args.map(arg => 
        typeof arg === 'object' ? JSON.stringify(arg) : String(arg)
      ).join(' ');
      
      // Filter out noise - only log genuine app errors
      if (!message.includes('DevTools') && 
          !message.includes('LaunchDarkly') &&
          !message.includes('@import rules') &&
          !message.includes('Network Error') &&
          !message.includes('AxiosError') &&
          !message.includes('WebSocket') &&
          !message.includes('isTrusted') &&
          !message.includes('/errors/log/') &&
          !message.includes('PIDS Error Logger') &&
          (message.toLowerCase().includes('error') || 
           message.toLowerCase().includes('failed') ||
           message.toLowerCase().includes('exception'))) {
        this.logError(new Error(message.slice(0, 500)), 'frontend', { 
          type: 'ConsoleError' 
        });
      }
      
      originalConsoleError.apply(console, args);
    };

    console.log('[PIDS] Error logger initialized');
  }
}

export default ErrorLogger;