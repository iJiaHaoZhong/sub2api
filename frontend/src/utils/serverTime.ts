/**
 * Server Time Offset Utility
 * Calculates the offset between server time and local time
 * so that time comparisons in the frontend use server time.
 */

let serverTimeOffset = 0

/**
 * Update the server time offset from an HTTP response Date header.
 * Called from the API client response interceptor.
 */
export function updateServerTimeOffset(serverDateHeader: string | null): void {
  if (!serverDateHeader) return
  const serverTime = new Date(serverDateHeader).getTime()
  if (isNaN(serverTime)) return
  serverTimeOffset = serverTime - Date.now()
}

/**
 * Get the current server time as a Date object.
 * Uses the calculated offset to adjust local time.
 */
export function serverNow(): Date {
  return new Date(Date.now() + serverTimeOffset)
}
