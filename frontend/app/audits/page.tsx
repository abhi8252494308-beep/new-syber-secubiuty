'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { FileText, Loader2, RefreshCw, Download } from 'lucide-react';
import api from '@/lib/api';
import { isAuthenticated } from '@/lib/auth';

interface AuditSummary {
  id: string;
  domain_id: string;
  domain_name: string;
  status: string;
  overall_score: number | null;
  created_at: string;
  completed_at: string | null;
}

export default function AuditsPage() {
  const router = useRouter();
  const [audits, setAudits] = useState<AuditSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<string>('all');

  useEffect(() => {
    if (!isAuthenticated()) {
      router.push('/auth/login');
      return;
    }
    fetchAudits();
  }, []);

  const fetchAudits = async () => {
    try {
      const response = await api.get('/audits');
      setAudits(response.data);
    } catch (error) {
      console.error('Failed to fetch audits:', error);
    } finally {
      setLoading(false);
    }
  };

  const filteredAudits = audits.filter((audit) => {
    if (filter === 'all') return true;
    return audit.status === filter;
  });

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary-600" />
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Audits</h1>
          <p className="text-gray-600 mt-1">View and manage your security audits</p>
        </div>
        <div className="flex items-center space-x-3">
          <select
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="input w-auto"
          >
            <option value="all">All Status</option>
            <option value="completed">Completed</option>
            <option value="running">Running</option>
            <option value="pending">Pending</option>
            <option value="failed">Failed</option>
          </select>
          <button onClick={fetchAudits} className="btn-secondary p-2">
            <RefreshCw className="h-5 w-5" />
          </button>
        </div>
      </div>

      {filteredAudits.length === 0 ? (
        <div className="card text-center py-12">
          <FileText className="h-12 w-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-gray-900 mb-2">No audits found</h3>
          <p className="text-gray-600 mb-4">Run your first audit on a verified domain</p>
          <Link href="/domains" className="btn-primary">
            Go to Domains
          </Link>
        </div>
      ) : (
        <div className="grid gap-4">
          {filteredAudits.map((audit) => (
            <Link key={audit.id} href={`/audits/${audit.id}`} className="card hover:shadow-md transition-shadow">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="font-semibold text-gray-900">{audit.domain_name}</h3>
                  <p className="text-sm text-gray-600">
                    {new Date(audit.created_at).toLocaleDateString()} at{' '}
                    {new Date(audit.created_at).toLocaleTimeString()}
                  </p>
                </div>
                <div className="flex items-center space-x-4">
                  <StatusBadge status={audit.status} />
                  {audit.overall_score !== null && (
                    <ScoreBadge score={audit.overall_score} />
                  )}
                </div>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    completed: 'badge-success',
    running: 'badge-info',
    pending: 'badge-warning',
    failed: 'badge-error',
  };
  return <span className={styles[status] || 'badge-info'}>{status}</span>;
}

function ScoreBadge({ score }: { score: number }) {
  const color = score >= 80 ? 'text-green-600' : score >= 50 ? 'text-yellow-600' : 'text-red-600';
  return <span className={`font-semibold text-lg ${color}`}>{score}%</span>;
}