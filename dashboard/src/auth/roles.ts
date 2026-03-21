export type Role = 'admin' | 'auditor' | 'operator' | 'viewer';

export interface Permission {
  viewDashboards: boolean;
  runValidate: boolean;
  managePolicies: boolean;
  resolveAppeals: boolean;
  manageUsers: boolean;
  exportReports: boolean;
}

const PERMISSIONS: Record<Role, Permission> = {
  admin:    { viewDashboards: true, runValidate: true, managePolicies: true, resolveAppeals: true, manageUsers: true, exportReports: true },
  auditor:  { viewDashboards: true, runValidate: false, managePolicies: false, resolveAppeals: true, manageUsers: false, exportReports: true },
  operator: { viewDashboards: true, runValidate: true, managePolicies: true, resolveAppeals: false, manageUsers: false, exportReports: true },
  viewer:   { viewDashboards: true, runValidate: false, managePolicies: false, resolveAppeals: false, manageUsers: false, exportReports: false },
};

export function getPermissions(role: Role): Permission {
  return PERMISSIONS[role] ?? PERMISSIONS.viewer;
}
