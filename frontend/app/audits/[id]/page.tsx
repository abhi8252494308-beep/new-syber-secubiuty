'use client';

import { useState, useEffect } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import {
  ArrowLeft,
  Shield,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Lock,
  FileCode,
  Cookie,
  Bot,
  FileCheck,
  Server,
  Download,
  RefreshCw,
  Loader2,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ExternalLink,
} from 'lucide-react';
import api from '@/lib/api';

interface AuditDetail {
  id: string;
  domain_id: string;
  status: string;
  started_at: string | null;
  completed_at: string | null;
  overall_score: number | null;
  error_message: string | null;
  created_at: string;
  updated_at: string;
  results: {
    id: string;
    check_category: string;
    check_name: string;
    status: string;
    score: number;
    max_score: number;
    details: Record<string, any> | null;
    recommendations: string[] | null;
  }[];
  tls_result: {
    has_https: boolean;
    tls_version: string | null;
    cipher_suite: string | null;
    certificate_valid: boolean;
    certificate_issuer: string | null;
    certificate_subject: string | null;
    certificate_not_before: string | null;
    certificate_not_after: string | null;
    certificate_days_remaining: number | null;
    hsts_enabled: boolean;
    hsts_max_age: number | null;
    hsts_include_subdomains: boolean;
    hsts_preload: boolean;
  } | null;
  header_result: {
    content_security_policy: string | null;
    csp_valid: boolean;
    x_frame_options: string | null;
    x_content_type_options: string | null;
    x_xss_protection: string | null;
    referrer_policy: string | null;
    permissions_policy: string | null;
    strict_transport_security: string | null;
    cross_origin_opener_policy: string | null;
    cross_origin_resource_policy: string | null;
    cross_origin_embedder_policy: string | null;
  } | null;
  cookie_results: {
    cookie_name: string;
    has_secure_flag: boolean;
    has_httponly_flag: boolean;
    has_samesite_flag: boolean;
    samesite_value: string | null;
  }[];
  robots_result: {
    exists: boolean;
    content: string | null;
    sitemap_urls: string[] | null;
    has_security_txt_reference: boolean;
  } | null;
  security_txt_result: {
    exists: boolean;
    content: string | null;
    contact_urls: string[] | null;
    expires: string | null;
    encryption_urls: string[] | null;
    policy_urls: string[] | null;
  } | null;
  server_info_result: {
    server_header: string | null;
    x_powered_by: string | null;
    technology_stack: Record<string, any> | null;
    ip_address: string | null;
    country: string | null;
    isp: string | null;
  } | null;
}

interface DomainInfo {
  id: string;
  domain_name: string;
  is_verified: boolean;
}

export default function AuditDetailPage() {
  const params = useParams();
  const router = useRouter();
  const auditId = params?.id as string;

  const [audit, setAudit] = useState<AuditDetail | null>(null);
  const [domain, setDomain] = useState<DomainInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [generatingReport, setGeneratingReport] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (auditId) {
      fetchAudit();
    }
  }, [auditId]);

  const fetchAudit = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.get(`/audits/${auditId}`);
      setAudit(res.data);

      if (res.data?.domain_id) {
        try {
          const domRes = await api.get(`/domains/${res.data.domain_id}`);
          setDomain(domRes.data);
        } catch {
          // fallback
        }
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load audit details');
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadReport = async () => {
    if (!audit) return;
    try {
      setGeneratingReport(true);
      const genRes = await api.post(`/reports/generate/${audit.id}`);
      const reportId = genRes.data.report_id;
      
      const baseURL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';
      window.open(`${baseURL}/reports/download/${reportId}`, '_blank');
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to generate report');
    } finally {
      setGeneratingReport(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary-600" />
      </div>
    );
  }

  if (error || !audit) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-12 text-center">
        <ShieldAlert className="h-16 w-16 text-red-500 mx-auto mb-4" />
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Audit Not Found</h2>
        <p className="text-gray-600 mb-6">{error || 'Could not find the requested audit.'}</p>
        <Link href="/audits" className="btn-primary inline-flex items-center space-x-2">
          <ArrowLeft className="h-4 w-4" />
          <span>Back to Audits</span>
        </Link>
      </div>
    );
  }

  const score = audit.overall_score ?? 0;
  const scoreColor = score >= 80 ? 'text-green-600' : score >= 50 ? 'text-yellow-600' : 'text-red-600';
  const scoreBg = score >= 80 ? 'bg-green-50 border-green-200' : score >= 50 ? 'bg-yellow-50 border-yellow-200' : 'bg-red-50 border-red-200';

  const categoryIcons: Record<string, any> = {
    tls: Lock,
    headers: FileCode,
    cookies: Cookie,
    robots: Bot,
    security_txt: FileCheck,
    server_info: Server,
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Top navigation */}
      <div className="flex items-center justify-between">
        <Link href="/audits" className="text-gray-600 hover:text-gray-900 inline-flex items-center space-x-1 text-sm font-medium">
          <ArrowLeft className="h-4 w-4" />
          <span>Back to Audits</span>
        </Link>
        <div className="flex items-center space-x-3">
          <button onClick={fetchAudit} className="btn-secondary flex items-center space-x-1 text-sm">
            <RefreshCw className="h-4 w-4" />
            <span>Refresh</span>
          </button>
          {audit.status === 'completed' && (
            <button
              onClick={handleDownloadReport}
              disabled={generatingReport}
              className="btn-primary flex items-center space-x-2 text-sm"
            >
              {generatingReport ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
              <span>Download PDF Report</span>
            </button>
          )}
        </div>
      </div>

      {/* Header Banner */}
      <div className="card bg-white border border-gray-200">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div>
            <div className="flex items-center space-x-3">
              <h1 className="text-2xl sm:text-3xl font-bold text-gray-900">
                {domain?.domain_name || 'Website Audit'}
              </h1>
              {domain?.domain_name && (
                <a
                  href={`https://${domain.domain_name}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-gray-400 hover:text-primary-600"
                >
                  <ExternalLink className="h-5 w-5" />
                </a>
              )}
            </div>
            <p className="text-sm text-gray-500 mt-1">
              Audit ID: <span className="font-mono text-xs text-gray-700">{audit.id}</span>
            </p>
            <div className="flex flex-wrap items-center gap-4 mt-3 text-sm text-gray-600">
              <div>
                Status:{' '}
                <span
                  className={`inline-block px-2 py-0.5 rounded-full text-xs font-semibold uppercase ${
                    audit.status === 'completed'
                      ? 'bg-green-100 text-green-800'
                      : audit.status === 'running'
                      ? 'bg-blue-100 text-blue-800 animate-pulse'
                      : audit.status === 'failed'
                      ? 'bg-red-100 text-red-800'
                      : 'bg-yellow-100 text-yellow-800'
                  }`}
                >
                  {audit.status}
                </span>
              </div>
              <div>
                Date:{' '}
                <span className="font-medium text-gray-900">
                  {audit.completed_at
                    ? new Date(audit.completed_at).toLocaleString()
                    : new Date(audit.created_at).toLocaleString()}
                </span>
              </div>
            </div>
          </div>

          {/* Overall Score Box */}
          <div className={`p-6 rounded-xl border flex items-center space-x-4 ${scoreBg}`}>
            <div>
              <p className="text-xs uppercase font-bold tracking-wider text-gray-500">Security Score</p>
              <div className="flex items-baseline space-x-1">
                <span className={`text-4xl font-extrabold ${scoreColor}`}>{score}</span>
                <span className="text-gray-500 font-medium">/100</span>
              </div>
            </div>
            {score >= 80 ? (
              <ShieldCheck className="h-12 w-12 text-green-600" />
            ) : score >= 50 ? (
              <ShieldAlert className="h-12 w-12 text-yellow-600" />
            ) : (
              <ShieldX className="h-12 w-12 text-red-600" />
            )}
          </div>
        </div>
      </div>

      {/* Category Results Grid */}
      <div className="space-y-4">
        <div className="flex items-center space-x-2 border-b border-gray-200 pb-2">
          <span className="font-semibold text-gray-900 text-base">
            Audit Checks ({audit.results?.length || 0})
          </span>
        </div>

        <div className="grid gap-4">
          {audit.results?.map((res) => {
            const Icon = categoryIcons[res.check_category] || Shield;
            const isPass = res.status.toLowerCase() === 'pass';

            return (
              <div key={res.id} className="card border-l-4 border-l-primary-500 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <div className={`p-2 rounded-lg ${isPass ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
                      <Icon className="h-5 w-5" />
                    </div>
                    <div>
                      <h3 className="font-semibold text-gray-900 text-base">{res.check_name}</h3>
                      <p className="text-xs text-gray-500 uppercase tracking-wide">{res.check_category}</p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-3">
                    <span className="text-sm font-semibold text-gray-700">
                      Score: {res.score} / {res.max_score}
                    </span>
                    <span
                      className={`inline-flex items-center space-x-1 px-2.5 py-1 rounded-full text-xs font-semibold uppercase ${
                        isPass ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                      }`}
                    >
                      {isPass ? <CheckCircle2 className="h-3.5 w-3.5" /> : <XCircle className="h-3.5 w-3.5" />}
                      <span>{res.status}</span>
                    </span>
                  </div>
                </div>

                {/* Recommendations */}
                {res.recommendations && res.recommendations.length > 0 && (
                  <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 text-sm">
                    <div className="flex items-center space-x-1.5 text-amber-800 font-semibold mb-1">
                      <AlertTriangle className="h-4 w-4" />
                      <span>Actionable Recommendations:</span>
                    </div>
                    <ul className="list-disc list-inside space-y-1 text-amber-900 text-xs sm:text-sm pl-2">
                      {res.recommendations.map((rec, i) => (
                        <li key={i}>{rec}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Details Table */}
                {res.details && Object.keys(res.details).length > 0 && (
                  <div className="bg-gray-50 rounded-lg p-3 text-xs overflow-x-auto">
                    <table className="w-full">
                      <tbody>
                        {Object.entries(res.details).map(([k, v]) => (
                          <tr key={k} className="border-b border-gray-200/50 last:border-0">
                            <td className="py-1 pr-4 font-semibold text-gray-600 capitalize">
                              {k.replace(/_/g, ' ')}
                            </td>
                            <td className="py-1 text-gray-900 font-mono">
                              {typeof v === 'boolean'
                                ? v
                                  ? 'True (Enabled)'
                                  : 'False (Disabled)'
                                : v === null
                                ? 'Not Set'
                                : typeof v === 'object'
                                ? JSON.stringify(v)
                                : String(v)}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
