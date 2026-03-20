import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';
import { useAuth } from '../auth/AuthContext';
import { LogOut, User } from 'lucide-react';

export default function Layout() {
  const { user, logout } = useAuth();

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <header className="h-14 border-b bg-white dark:bg-gray-800 flex items-center justify-between px-6 shrink-0">
          <h2 className="text-lg font-semibold">BuildToValue</h2>
          <div className="flex items-center gap-4">
            <span className="text-sm text-gray-500 flex items-center gap-1">
              <User size={14} />
              {user?.username}
              <span className="ml-1 px-2 py-0.5 text-xs rounded-full bg-btv-100 text-btv-700 dark:bg-btv-900 dark:text-btv-200">
                {user?.role}
              </span>
            </span>
            <button onClick={logout} className="text-gray-400 hover:text-red-500" title="Logout">
              <LogOut size={18} />
            </button>
          </div>
        </header>
        <main className="flex-1 overflow-y-auto p-6 bg-gray-50 dark:bg-gray-900">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
