'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { Plus, Globe, CheckCircle, XCircle, Loader2, Trash2, Play, Copy, Check, Info, ShieldCheck, ChevronDown, ChevronUp } from 'lucide-react';
import api from '@/lib/api';

interface Domain {
  id: string;
  domain_name: string;
  is_verified: boolean;
  verification_method: string;
  verification_token?: string | null;
  is_active: boolean;
  last_audit_at: string | null;
  created_at: string;
}

export default function DomainsPage() {
  const router = useRouter();
  const [domains, setDomains] = useState<Domain[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAddForm, setShowAddForm] = useState(false);
  const [newDomain, setNewDomain] = useState('');
  const [verificationMethod, setVerificationMethod] = useState('dns');
  const [adding, setAdding] = useState(false);
  const [error, setError] = useState('');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<Record<string, boolean>>({});

  useEffect(() => {
    fetchDomains();
  }, []);

  const fetchDomains = async () => {
    try {
      const response = await api.get('/domains');
      setDomains(response.data);
    } catch (error) {
      console.error('Failed to fetch domains:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleAddDomain = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setAdding(true);

    try {
      const res = await api.post('/domains', {
        domain_name: newDomain,
        verification_method: verificationMethod,
      });
      setNewDomain('');
      setShowAddForm(false);
      await fetchDomains();
      if (res.data?.id) {
        setExpandedId(res.data.id);
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to add domain');
    } finally {
      setAdding(false);
    }
  };

  const handleVerify = async (domainId: string) => {
    setActionLoading((prev) => ({ ...prev, [domainId]: true }));
    try {
      const response = await api.post(`/domains/${domainId}/verify`);
      alert(response.data.message || 'Verification completed');
      await fetchDomains();
    } catch (error: any) {
      alert(error.response?.data?.detail || 'Failed to verify domain');
    } finally {
      setActionLoading((prev) => ({ ...prev, [domainId]: false }));
    }
  };

  const handleDelete = async (domainId: string) => {
    if (!confirm('Are you sure you want to delete this domain?')) return;
    try {
      await api.delete(`/domains/${domainId}`);
      await fetchDomains();
    } catch (error) {
      console.error('Failed to delete domain:', error);
    }
  };

  const handleRunAudit = async (domainId: string) => {
    setActionLoading((prev) => ({ ...prev, [domainId]: true }));
    try {
      const res = await api.post('/audits', { domain_id: domainId });
      router.push(`/audits/${res.data.id}`);
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to start audit');
      setActionLoading((prev) => ({ ...prev, [domainId]: false }));
    }
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
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
          <h1 className="text-3xl font-bold text-gray-900">Domains</h1>
          <p className="text-gray-600 mt-1">Manage and verify websites for security auditing</p>
        </div>
        <button
          onClick={() => setShowAddForm(true)}
          className="btn-primary flex items-center space-x-2"
        >
          <Plus className="h-5 w-5" />
          <span>Add Domain</span>
        </button>
      </div>

      {/* Add Domain Form */}
      {showAddForm && (
        <div className="card mb-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Add New Domain</h3>
          {error && (
            <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg mb-4">
              {error}
            </div>
          )}
          <form onSubmit={handleAddDomain} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Domain Name</label>
              <input
                type="text"
                required
                value={newDomain}
                onChange={(e) => setNewDomain(e.target.value)}
                className="input"
                placeholder="example.com"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Verification Method</label>
              <select
                value={verificationMethod}
                onChange={(e) => setVerificationMethod(e.target.value)}
                className="input"
              >
                <option value="dns">DNS TXT Record (Recommended)</option>
                <option value="file">File Upload (.well-known)</option>
                <option value="meta">Meta Tag HTML</option>
              </select>
            </div>
            <div className="flex space-x-3">
              <button type="submit" disabled={adding} className="btn-primary flex items-center space-x-2">
                {adding && <Loader2 className="h-4 w-4 animate-spin" />}
                <span>{adding ? 'Adding...' : 'Add Domain'}</span>
              </button>
              <button
                type="button"
                onClick={() => setShowAddForm(false)}
                className="btn-secondary"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Domains List */}
      {domains.length === 0 ? (
        <div className="card text-center py-12">
          <Globe className="h-12 w-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-gray-900 mb-2">No domains yet</h3>
          <p className="text-gray-600 mb-4">Add your first domain to start auditing</p>
          <button onClick={() => setShowAddForm(true)} className="btn-primary">
            Add Domain
          </button>
        </div>
      ) : (
        <div className="grid gap-4">
          {domains.map((domain) => {
            const isExpanded = expandedId === domain.id;
            const isLoadingAction = actionLoading[domain.id];

            return (
              <div key={domain.id} className="card space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div className="flex items-center space-x-4">
                    <div className={`p-2.5 rounded-full ${domain.is_verified ? 'bg-green-100' : 'bg-yellow-100'}`}>
                      {domain.is_verified ? (
                        <CheckCircle className="h-6 w-6 text-green-600" />
                      ) : (
                        <XCircle className="h-6 w-6 text-yellow-600" />
                      )}
                    </div>
                    <div>
                      <h3 className="font-semibold text-gray-900 text-lg">{domain.domain_name}</h3>
                      <p className="text-sm text-gray-600">
                        {domain.is_verified ? 'Verified & Ready' : 'Pending Verification'} • Method: <span className="font-medium uppercase text-xs">{domain.verification_method}</span>
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2 flex-wrap">
                    {!domain.is_verified && (
                      <>
                        <button
                          onClick={() => setExpandedId(isExpanded ? null : domain.id)}
                          className="btn-secondary text-sm flex items-center space-x-1"
                        >
                          <Info className="h-4 w-4" />
                          <span>Instructions</span>
                          {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                        </button>
                        <button
                          onClick={() => handleVerify(domain.id)}
                          disabled={isLoadingAction}
                          className="btn-primary text-sm flex items-center space-x-1"
                        >
                          {isLoadingAction ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
                          <span>Verify</span>
                        </button>
                      </>
                    )}

                    {domain.is_verified && (
                      <button
                        onClick={() => handleRunAudit(domain.id)}
                        disabled={isLoadingAction}
                        className="btn-primary text-sm flex items-center space-x-1.5"
                      >
                        {isLoadingAction ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
                        <span>Run Audit</span>
                      </button>
                    )}

                    <button
                      onClick={() => handleDelete(domain.id)}
                      className="p-2 text-red-600 hover:bg-red-50 rounded-lg"
                      title="Delete domain"
                    >
                      <Trash2 className="h-5 w-5" />
                    </button>
                  </div>
                </div>

                {/* Verification instructions box */}
                {!domain.is_verified && isExpanded && domain.verification_token && (
                  <div className="bg-slate-50 border border-slate-200 rounded-lg p-4 text-sm space-y-3 mt-3">
                    <div className="font-semibold text-slate-800 flex items-center space-x-2">
                      <Info className="h-4 w-4 text-primary-600" />
                      <span>How to verify ownership for {domain.domain_name}:</span>
                    </div>

                    {domain.verification_method === 'dns' && (
                      <div className="space-y-2 text-slate-700 text-xs sm:text-sm">
                        <p>Add the following <b>TXT Record</b> to your DNS settings:</p>
                        <div className="bg-white p-2.5 rounded border font-mono text-xs space-y-1">
                          <div><b>Host / Name:</b> _securesite-audit.{domain.domain_name}</div>
                          <div><b>Type:</b> TXT</div>
                          <div className="flex items-center justify-between">
                            <span><b>Value:</b> {domain.verification_token}</span>
                            <button
                              onClick={() => handleCopy(domain.verification_token!, `tok-${domain.id}`)}
                              className="text-primary-600 hover:text-primary-700 flex items-center space-x-1 text-xs"
                            >
                              {copiedId === `tok-${domain.id}` ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                              <span>{copiedId === `tok-${domain.id}` ? 'Copied' : 'Copy'}</span>
                            </button>
                          </div>
                        </div>
                      </div>
                    )}

                    {domain.verification_method === 'file' && (
                      <div className="space-y-2 text-slate-700 text-xs sm:text-sm">
                        <p>Upload a file to your web server at the following URL:</p>
                        <div className="bg-white p-2.5 rounded border font-mono text-xs space-y-1">
                          <div><b>URL:</b> https://{domain.domain_name}/.well-known/securesite-audit-verification.txt</div>
                          <div className="flex items-center justify-between">
                            <span><b>File Content:</b> {domain.verification_token}</span>
                            <button
                              onClick={() => handleCopy(domain.verification_token!, `tok-${domain.id}`)}
                              className="text-primary-600 hover:text-primary-700 flex items-center space-x-1 text-xs"
                            >
                              {copiedId === `tok-${domain.id}` ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                              <span>{copiedId === `tok-${domain.id}` ? 'Copied' : 'Copy'}</span>
                            </button>
                          </div>
                        </div>
                      </div>
                    )}

                    {domain.verification_method === 'meta' && (
                      <div className="space-y-2 text-slate-700 text-xs sm:text-sm">
                        <p>Add this <b>Meta Tag</b> inside the &lt;head&gt; section of your homepage HTML:</p>
                        <div className="bg-white p-2.5 rounded border font-mono text-xs flex items-center justify-between">
                          <span>&lt;meta name=&quot;securesite-audit-verification&quot; content=&quot;{domain.verification_token}&quot;&gt;</span>
                          <button
                            onClick={() => handleCopy(`<meta name="securesite-audit-verification" content="${domain.verification_token}">`, `meta-${domain.id}`)}
                            className="text-primary-600 hover:text-primary-700 flex items-center space-x-1 text-xs ml-2"
                          >
                            {copiedId === `meta-${domain.id}` ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                            <span>{copiedId === `meta-${domain.id}` ? 'Copied' : 'Copy'}</span>
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
