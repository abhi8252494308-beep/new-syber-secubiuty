'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { Globe, Shield, FileText, TrendingUp, Plus, Loader2 } from 'lucide-react';
import api from '@/lib/api';

interface DashboardStats {
  totalDomains: number;
  verifiedDomains: number;
  totalAudits: number;
  averageScore: number;
}

interface RecentAudit {
  id: string;
  domain_name: string;
  status: string;
  overall_score: number | null;
  created_at: string;
}

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats>({
    totalDomains: 0,
    verifiedDomains: 0,
    totalAudits: 0,
    averageScore: 0,
  });
  const [recentAudits, setRecentAudits] = useState<RecentAudit[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      const [domainsRes, auditsRes] = await Promise.all([
        api.get('/domains'),
        api.get('/audits'),
      ]);

      const domains = domainsRes.data;
      const audits = auditsRes.data;

      const verifiedDomains = domains.filter((d: any) => d.is_verified).length;
      const completedAudits = audits.filter((a: any) => a.overall_score !== null);
      const averageScore = completedAudits.length > 0
        ? Math.round(completedAudits.reduce((sum: number, a: any) => sum + a.overall_score, 0) / completedAudits.length)
        : 0;

      setStats({
        totalDomains: domains.length,
        verifiedDomains,
        totalAudits: audits.length,
        averageScore,
      });

      setRecentAudits(audits.slice(0, 5));
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary-600" />
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900">Dashboard</h1>
        <p className="text-gray-600 mt-1">Overview of your security audits</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <StatCard
          icon={<Globe className="h-6 w-6 text-primary-600" />}
          label="Total Domains"
          value={stats.totalDomains}
        />
        <StatCard
          icon={<Shield className="h-6 w-6 text-green-600" />}
          label="Verified Domains"
          value={stats.verifiedDomains}
        />
        <StatCard
          icon={<FileText className="h-6 w-6 text-blue-600" />}
          label="Total Audits"
          value={stats.totalAudits}
        />
        <StatCard
          icon={<TrendingUp className="h-6 w-6 text-purple-600" />}
          label="Average Score"
          value={`${stats.averageScore}%`}
        />
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
        <Link href="/domains" className="card hover:shadow-md transition-shadow flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">Add New Domain</h3>
            <p className="text-gray-600">Verify and audit a new website</p>
          </div>
          <Plus className="h-8 w-8 text-primary-600" />
        </Link>
        <Link href="/audits" className="card hover:shadow-md transition-shadow flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">View All Audits</h3>
            <p className="text-gray-600">See detailed audit results</p>
          </div>
          <FileText className="h-8 w-8 text-primary-600" />
        </Link>
      </div>

      {/* Recent Audits */}
      <div className="card">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Recent Audits</h2>
        {recentAudits.length === 0 ? (
          <p className="text-gray-600 text-center py-8">No audits yet. Add a domain to get started!</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-200">
                  <th className="text-left py-3 px-4 text-sm font-medium text-gray-600">Domain</th>
                  <th className="text-left py-3 px-4 text-sm font-medium text-gray-600">Status</th>
                  <th className="text-left py-3 px-4 text-sm font-medium text-gray-600">Score</th>
                  <th className="text-left py-3 px-4 text-sm font-medium text-gray-600">Date</th>
                </tr>
              </thead>
              <tbody>
                {recentAudits.map((audit) => (
                  <tr key={audit.id} className="border-b border-gray-100 hover:bg-gray-50">
                    <td className="py-3 px-4">
                      <Link href={`/audits/${audit.id}`} className="text-primary-600 hover:text-primary-700 font-medium">
                        {audit.domain_name}
                      </Link>
                    </td>
                    <td className="py-3 px-4">
                      <StatusBadge status={audit.status} />
                    </td>
                    <td className="py-3 px-4">
                      {audit.overall_score !== null ? (
                        <ScoreBadge score={audit.overall_score} />
                      ) : (
                        <span className="text-gray-400">-</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-gray-600">
                      {new Date(audit.created_at).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function StatCard({ icon, label, value }: { icon: React.ReactNode; label: string; value: string | number }) {
  return (
    <div className="card">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-600">{label}</p>
          <p className="text-2xl font-bold text-gray-900 mt-1">{value}</p>
        </div>
        {icon}
      </div>
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
  return <span className={`font-semibold ${color}`}>{score}%</span>;
}