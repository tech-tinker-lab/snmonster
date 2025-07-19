/**
 * Utility and helper functions for ManagedDevices page
 */

/**
 * Calculate the average security score from an array of security reports.
 * @param securityReports Array of security report objects
 * @returns Average score as a number, or null if no reports
 */
export function getAverageSecurityScore(securityReports: any[]): number | null {
  if (!securityReports.length) return null;
  const total = securityReports.reduce((acc, r) => acc + r.overall_score, 0);
  return total / securityReports.length;
}

/**
 * Calculate the total number of critical issues from all security reports.
 * @param securityReports Array of security report objects
 * @returns Total critical issues count
 */
export function getCriticalIssuesCount(securityReports: any[]): number {
  return securityReports.reduce((acc, r) => acc + Object.values(r.categories).reduce((catAcc: number, cat: any) => catAcc + cat.critical_issues, 0), 0);
}

/**
 * Format a category name for display (e.g., 'os_security' -> 'Os Security').
 * @param name Category name string
 * @returns Formatted string
 */
export function formatCategoryName(name: string): string {
  return name.replace('_', ' ').replace(/\b\w/g, (l) => l.toUpperCase());
}

/**
 * Update SSH credentials for a list of devices (bulk).
 * @param deviceAPI API object
 * @param deviceIds Array of device IDs
 * @param username SSH username
 * @param password SSH password
 * @returns Promise<void>
 */
export async function updateBulkCredentials(deviceAPI: any, deviceIds: number[], username: string, password: string): Promise<void> {
  const updatePromises = deviceIds.map(deviceId =>
    deviceAPI.updateDevice(deviceId, {
      ssh_username: username,
      ssh_password: password
    })
  );
  await Promise.all(updatePromises);
}

/**
 * Update SSH credentials for a single device.
 * @param deviceAPI API object
 * @param deviceId Device ID
 * @param username SSH username
 * @param password SSH password
 * @returns Promise<void>
 */
export async function updateSingleCredentials(deviceAPI: any, deviceId: number, username: string, password: string): Promise<void> {
  await deviceAPI.updateDevice(deviceId, {
    ssh_username: username,
    ssh_password: password
  });
}
