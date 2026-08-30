'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { FileText, Loader2, Download, Trash2, RefreshCw } from 'lucide-react';
import api from '@/lib/api';

interface ReportItem {
  id: string;
  audit_id: string;
  domain_name?: string;
  file_size: number;
  generated_at: string | null;
  download_count: number;
}

export default function ReportsPage() {
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchReports();
  }, []);

  const fetchReports = async () => {
    try {
      setLoading(true);
      const res = await api.get('/reports');
      setReports(res.data);
    } catch (err) {
      console.error('Failed to fetch reports:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = (reportId: string) => {
    const baseURL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';
    window.open(`${baseURL}/reports/download/${reportId}`, '_blank');
  };

  const handleDelete = async (reportId: string) => {
    if (!confirm('Are you sure you want to delete this report?')) return;
    try {
      await api.delete(`/reports/${reportId}`);
      fetchReports();
    } catch (err) {
      console.error('Failed to delete report:', err);
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
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Reports</h1>
          <p className="text-gray-600 mt-1">View and download generated PDF security audit reports</p>
        </div>
        <button onClick={fetchReports} className="btn-secondary p-2.5">
          <RefreshCw className="h-5 w-5" />
        </button>
      </div>

      {reports.length === 0 ? (
        <div className="card text-center py-12">
          <FileText className="h-12 w-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-gray-900 mb-2">No reports generated yet</h3>
          <p className="text-gray-600 mb-4">Complete an audit and click &quot;Download PDF Report&quot; to generate one</p>
          <Link href="/audits" className="btn-primary">
            Go to Audits
          </Link>
        </div>
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-200">
                <th className="text-left py-3 px-4 text-sm font-medium text-gray-600">Domain</th>
                <th className="text-left py-3 px-4 text-sm font-medium text-gray-600">File Size</th>
                <th className="text-left py-3 px-4 text-sm font-medium text-gray-600">Generated Date</th>
                <th className="text-left py-3 px-4 text-sm font-medium text-gray-600">Downloads</th>
                <th className="text-right py-3 px-4 text-sm font-medium text-gray-600">Actions</th>
              </tr>
            </thead>
            <tbody>
              {reports.map((report) => (
                <tr key={report.id} className="border-b border-gray-100 hover:bg-gray-50">
                  <td className="py-3 px-4 font-semibold text-gray-900">
                    <Link href={`/audits/${report.audit_id}`} className="text-primary-600 hover:text-primary-700">
                      {report.domain_name || 'Website Audit'}
                    </Link>
                  </td>
                  <td className="py-3 px-4 text-gray-600 text-sm">
                    {Math.round(report.file_size / 1024)} KB
                  </td>
                  <td className="py-3 px-4 text-gray-600 text-sm">
                    {report.generated_at ? new Date(report.generated_at).toLocaleString() : '-'}
                  </td>
                  <td className="py-3 px-4 text-gray-600 text-sm">
                    {report.download_count}
                  </td>
                  <td className="py-3 px-4 text-right space-x-2">
                    <button
                      onClick={() => handleDownload(report.id)}
                      className="btn-primary text-xs py-1.5 px-3 inline-flex items-center space-x-1"
                    >
                      <Download className="h-3.5 w-3.5" />
                      <span>Download</span>
                    </button>
                    <button
                      onClick={() => handleDelete(report.id)}
                      className="p-1.5 text-red-600 hover:bg-red-50 rounded"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
