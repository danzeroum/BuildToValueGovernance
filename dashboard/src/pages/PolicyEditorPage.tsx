import { useState, useCallback } from 'react';
import { governance } from '../api/client';

export default function PolicyEditorPage() {
  const [files, setFiles] = useState<string[]>([]);
  const [selected, setSelected] = useState('');
  const [content, setContent] = useState('');
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const [loaded, setLoaded] = useState(false);

  const loadFiles = useCallback(async () => {
    try {
      const { data } = await governance.get('/v1/policies');
      setFiles(data.files ?? data ?? []);
      setLoaded(true);
    } catch (e: any) {
      setError('Policy listing not available yet. Add GET /v1/policies endpoint.');
    }
  }, []);

  async function loadFile(path: string) {
    try {
      const { data } = await governance.get(`/v1/policies/${encodeURIComponent(path)}`);
      setContent(typeof data === 'string' ? data : JSON.stringify(data, null, 2));
      setSelected(path);
      setError('');
    } catch (e: any) {
      setError(`Failed to load ${path}: ${e.message}`);
    }
  }

  async function handleSave() {
    if (!selected) return;
    setSaving(true);
    try {
      await governance.put(`/v1/policies/${encodeURIComponent(selected)}`, { content });
      setError('');
      alert('Policy saved');
    } catch (e: any) {
      setError(`Save failed: ${e.message}`);
    } finally {
      setSaving(false);
    }
  }

  async function handleValidate() {
    try {
      const { data } = await governance.post('/v1/policies/validate', { content });
      if (data.valid) {
        setError('');
        alert('YAML is valid');
      } else {
        setError(`Validation errors: ${JSON.stringify(data.errors)}`);
      }
    } catch (e: any) {
      setError(`Validation failed: ${e.message}`);
    }
  }

  return (
    <div>
      <h1 className="text-xl font-bold mb-4">YAML Policy Editor</h1>

      <div className="flex gap-6 h-[calc(100vh-200px)]">
        {/* File list */}
        <div className="w-56 border rounded-lg overflow-y-auto bg-white dark:bg-gray-800 shrink-0">
          <div className="p-3 border-b flex items-center justify-between">
            <span className="text-sm font-medium">Policies</span>
            <button onClick={loadFiles} className="text-xs text-btv-600 hover:underline">
              {loaded ? 'Refresh' : 'Load'}
            </button>
          </div>
          <div className="p-2">
            {files.length === 0 && <p className="text-xs text-gray-400 p-2">Click Load to list policies</p>}
            {files.map(f => (
              <button key={f} onClick={() => loadFile(f)}
                className={`w-full text-left text-xs px-2 py-1.5 rounded hover:bg-gray-50 dark:hover:bg-gray-700 ${selected === f ? 'bg-btv-50 text-btv-700 dark:bg-btv-900/30' : ''}`}
              >{f}</button>
            ))}
          </div>
        </div>

        {/* Editor */}
        <div className="flex-1 flex flex-col">
          <div className="flex items-center gap-2 mb-2">
            <span className="text-sm text-gray-500 flex-1">{selected || 'Select a policy file'}</span>
            <button onClick={handleValidate} disabled={!content}
              className="px-3 py-1 text-sm border rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50"
            >Validate</button>
            <button onClick={handleSave} disabled={!selected || saving}
              className="px-3 py-1 text-sm bg-btv-600 text-white rounded-lg hover:bg-btv-700 disabled:opacity-50"
            >{saving ? 'Saving...' : 'Save'}</button>
          </div>
          <textarea
            value={content}
            onChange={e => setContent(e.target.value)}
            placeholder="Select a policy file to edit..."
            className="flex-1 w-full px-4 py-3 border rounded-lg font-mono text-sm resize-none dark:bg-gray-800 dark:border-gray-700"
            spellCheck={false}
          />
          {error && <p className="text-red-600 text-sm mt-2">{error}</p>}
        </div>
      </div>
    </div>
  );
}
