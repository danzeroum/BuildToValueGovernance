import { NavLink } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';
import {
  Shield, Eraser, Heart, FileCheck, Brain, BookOpen,
  Scale, Bell, AlertTriangle, BarChart3, FileCode,
} from 'lucide-react';
import clsx from 'clsx';

const NAV_ITEMS = [
  { to: '/validate', label: 'Validate', icon: Shield },
  { to: '/sanitize', label: 'Sanitize', icon: Eraser },
  { to: '/trust', label: 'Trust Score', icon: Heart },
  { to: '/compliance', label: 'Compliance', icon: FileCheck },
  { to: '/intelligence', label: 'Intelligence', icon: Brain },
  { to: '/audit', label: 'Audit Ledger', icon: BookOpen },
  { to: '/appeals', label: 'Appeals', icon: Scale },
  { to: '/webhooks', label: 'Webhooks', icon: Bell },
  { to: '/fria', label: 'FRIA', icon: AlertTriangle },
  { to: '/metrics', label: 'Metrics', icon: BarChart3 },
  { to: '/policies', label: 'Policy Editor', icon: FileCode, requirePolicy: true },
];

export default function Sidebar() {
  const { permissions } = useAuth();

  return (
    <aside className="w-56 bg-white dark:bg-gray-800 border-r shrink-0 flex flex-col">
      <div className="h-14 flex items-center px-4 border-b">
        <span className="text-lg font-bold text-btv-600">BTV</span>
        <span className="ml-2 text-xs text-gray-400">v2.4</span>
      </div>
      <nav className="flex-1 py-2 overflow-y-auto">
        {NAV_ITEMS.map((item) => {
          if (item.requirePolicy && !permissions.managePolicies) return null;
          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                clsx(
                  'flex items-center gap-3 px-4 py-2.5 text-sm font-medium transition-colors',
                  isActive
                    ? 'bg-btv-50 text-btv-700 border-r-2 border-btv-600 dark:bg-btv-900/30 dark:text-btv-300'
                    : 'text-gray-600 hover:bg-gray-50 dark:text-gray-400 dark:hover:bg-gray-700/50',
                )
              }
            >
              <Icon size={18} />
              {item.label}
            </NavLink>
          );
        })}
      </nav>
      <div className="p-4 border-t text-xs text-gray-400">
        Sovereign Trust OS
      </div>
    </aside>
  );
}
