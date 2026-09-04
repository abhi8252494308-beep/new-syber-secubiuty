'use client';

import { useState, useEffect, useRef } from 'react';
import { Globe, Shield, FileText, TrendingUp, Loader2, AlertTriangle, CheckCircle, XCircle } from 'lucide-react';
import api from '@/lib/api';

interface RiskDistributionItem {
  _id: number;
  count: number;
}

interface TopVulnerability {
  _id: string;
  count: number;
}

interface DashboardStats {
  total_audits: number;
  risk_distribution: RiskDistributionItem[];
  average_scores: {
    avg_risk: number;
    avg_score: number;
    min_risk: number;
    max_risk: number;
  };
  top_vulnerabilities: TopVulnerability[];
}

interface RecentAudit {
  id: string;
  domain: string;
  status: string;
  overall_score: number | null;
  risk_score: number;
  created_at: string;
}

export default function AdvancedDashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [recentAudits, setRecentAudits] = useState<RecentAudit[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  const riskChartRef = useRef<SVGSVGElement>(null);
  const scoreChartRef = useRef<SVGSVGElement>(null);
  const vulnChartRef = useRef<SVGSVGElement>(null);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      const [statsRes, auditsRes] = await Promise.all([
        api.get('/mongodb/statistics'),
        api.get('/mongodb/audits/recent?limit=10'),
      ]);

      setStats(statsRes.data);
      setRecentAudits(auditsRes.data);
    } catch (err) {
      setError('Failed to fetch dashboard data');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (stats) {
      drawRiskDistributionChart();
      drawScoreChart();
      drawVulnerabilityChart();
    }
  }, [stats]);

  const drawRiskDistributionChart = () => {
    if (!riskChartRef.current || !stats) return;
    
    const svg = d3.select(riskChartRef.current);
    svg.selectAll('*').remove();
    
    const data = stats.risk_distribution || [];
    if (data.length === 0) return;
    
    const width = 350;
    const height = 250;
    const margin = { top: 20, right: 20, bottom: 40, left: 50 };
    
    const x = d3.scaleLinear()
      .domain([0, 100])
      .range([margin.left, width - margin.right]);
    
    const y = d3.scaleBand()
      .domain(data.map(d => `${d._id}-${d._id + 9}`))
      .range([margin.top, height - margin.bottom])
      .padding(0.1);
    
    const maxCount = d3.max(data, d => d.count) || 1;
    const xCount = d3.scaleLinear()
      .domain([0, maxCount])
      .range([margin.left, width - margin.right]);
    
    // X axis (risk score)
    svg.append('g')
      .attr('transform', `translate(0,${height - margin.bottom})`)
      .call(d3.axisBottom(x).ticks(5).tickFormat(d => d + '%'))
      .selectAll('text')
      .style('font-size', '10px');
    
    // Y axis (count)
    svg.append('g')
      .attr('transform', `translate(${margin.left},0)`)
      .call(d3.axisLeft(y))
      .selectAll('text')
      .style('font-size', '10px');
    
    // Bars
    svg.selectAll('rect')
      .data(data)
      .enter()
      .append('rect')
      .attr('x', margin.left)
      .attr('y', d => y(`${d._id}-${d._id + 9}`) || 0)
      .attr('width', d => xCount(d.count) - margin.left)
      .attr('height', y.bandwidth())
      .attr('fill', d => {
        const risk = d._id;
        if (risk >= 70) return '#ef4444';
        if (risk >= 40) return '#f59e0b';
        return '#22c55e';
      })
      .attr('rx', 2);
    
    // Labels
    svg.selectAll('.bar-label')
      .data(data)
      .enter()
      .append('text')
      .attr('class', 'bar-label')
      .attr('x', d => xCount(d.count) + 5)
      .attr('y', d => (y(`${d._id}-${d._id + 9}`) || 0) + y.bandwidth() / 2 + 4)
      .style('font-size', '10px')
      .text(d => d.count);
    
    // Title
    svg.append('text')
      .attr('x', width / 2)
      .attr('y', 15)
      .attr('text-anchor', 'middle')
      .style('font-size', '14px')
      .style('font-weight', '600')
      .text('Risk Score Distribution');
  };

  const drawScoreChart = () => {
    if (!scoreChartRef.current || !stats) return;
    
    const svg = d3.select(scoreChartRef.current);
    svg.selectAll('*').remove();
    
    const avgScore = stats.average_scores?.avg_score || 0;
    const avgRisk = stats.average_scores?.avg_risk || 0;
    
    const width = 350;
    const height = 250;
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = 80;
    
    // Background circle
    svg.append('circle')
      .attr('cx', centerX)
      .attr('cy', centerY)
      .attr('r', radius)
      .attr('fill', 'none')
      .attr('stroke', '#e5e7eb')
      .attr('stroke-width', 20);
    
    // Score arc
    const scoreArc = d3.arc()
      .innerRadius(radius - 10)
      .outerRadius(radius + 10)
      .startAngle(-Math.PI / 2)
      .endAngle(-Math.PI / 2 + (avgScore / 100) * 2 * Math.PI);
    
    svg.append('path')
      .attr('d', () => scoreArc(null as any) ?? '')
      .attr('transform', `translate(${centerX},${centerY})`)
      .attr('fill', avgScore >= 70 ? '#22c55e' : avgScore >= 40 ? '#f59e0b' : '#ef4444');
    
    // Risk arc
    const riskArc = d3.arc()
      .innerRadius(radius - 10)
      .outerRadius(radius + 10)
      .startAngle(-Math.PI / 2)
      .endAngle(-Math.PI / 2 + (avgRisk / 100) * 2 * Math.PI);
    
    svg.append('path')
      .attr('d', () => riskArc(null as any) ?? '')
      .attr('transform', `translate(${centerX},${centerY})`)
      .attr('fill', '#3b82f6')
      .attr('opacity', 0.5);
    
    // Center text
    svg.append('text')
      .attr('x', centerX)
      .attr('y', centerY - 10)
      .attr('text-anchor', 'middle')
      .style('font-size', '28px')
      .style('font-weight', 'bold')
      .style('fill', avgScore >= 70 ? '#22c55e' : avgScore >= 40 ? '#f59e0b' : '#ef4444')
      .text(`${Math.round(avgScore)}%`);
    
    svg.append('text')
      .attr('x', centerX)
      .attr('y', centerY + 20)
      .attr('text-anchor', 'middle')
      .style('font-size', '12px')
      .style('fill', '#6b7280')
      .text('Average Security Score');
    
    // Legend
    const legend = svg.append('g')
      .attr('transform', `translate(${centerX - 80}, ${height - 30})`);
    
    legend.append('rect')
      .attr('width', 12)
      .attr('height', 12)
      .attr('fill', '#22c55e');
    legend.append('text')
      .attr('x', 18)
      .attr('y', 10)
      .style('font-size', '10px')
      .text('Security Score');
    
    legend.append('rect')
      .attr('x', 100)
      .attr('width', 12)
      .attr('height', 12)
      .attr('fill', '#3b82f6')
      .attr('opacity', 0.5);
    legend.append('text')
      .attr('x', 118)
      .attr('y', 10)
      .style('font-size', '10px')
      .text('Risk Score');
  };

  const drawVulnerabilityChart = () => {
    if (!vulnChartRef.current || !stats) return;
    
    const svg = d3.select(vulnChartRef.current);
    svg.selectAll('*').remove();
    
    const data = stats.top_vulnerabilities || [];
    if (data.length === 0) {
      svg.append('text')
        .attr('x', 175)
        .attr('y', 125)
        .attr('text-anchor', 'middle')
        .style('font-size', '14px')
        .style('fill', '#9ca3af')
        .text('No vulnerability data');
      return;
    }
    
    const width = 350;
    const height = 250;
    const margin = { top: 20, right: 10, bottom: 40, left: 200 };
    
    const y = d3.scaleBand()
      .domain(data.map(d => d._id.length > 40 ? d._id.substring(0, 40) + '...' : d._id))
      .range([margin.top, height - margin.bottom])
      .padding(0.2);
    
    const x = d3.scaleLinear()
      .domain([0, d3.max(data, d => d.count) || 1])
      .range([margin.left, width - margin.right]);
    
    // Y axis
    svg.append('g')
      .attr('transform', `translate(${margin.left},0)`)
      .call(d3.axisLeft(y))
      .selectAll('text')
      .style('font-size', '9px');
    
    // X axis
    svg.append('g')
      .attr('transform', `translate(0,${height - margin.bottom})`)
      .call(d3.axisBottom(x).ticks(5))
      .selectAll('text')
      .style('font-size', '10px');
    
    // Bars
    svg.selectAll('rect')
      .data(data)
      .enter()
      .append('rect')
      .attr('x', margin.left)
      .attr('y', d => y(d._id.length > 40 ? d._id.substring(0, 40) + '...' : d._id) || 0)
      .attr('width', d => x(d.count) - margin.left)
      .attr('height', y.bandwidth())
      .attr('fill', '#ef4444')
      .attr('rx', 2);
    
    // Labels
    svg.selectAll('.bar-label')
      .data(data)
      .enter()
      .append('text')
      .attr('class', 'bar-label')
      .attr('x', d => x(d.count) + 5)
      .attr('y', d => (y(d._id.length > 40 ? d._id.substring(0, 40) + '...' : d._id) || 0) + y.bandwidth() / 2 + 4)
      .style('font-size', '10px')
      .text(d => d.count);
    
    // Title
    svg.append('text')
      .attr('x', width / 2)
      .attr('y', 15)
      .attr('text-anchor', 'middle')
      .style('font-size', '14px')
      .style('font-weight', '600')
      .text('Top Vulnerabilities');
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary-600" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <XCircle className="h-16 w-16 text-red-500 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-gray-900">Failed to load dashboard</h2>
          <p className="text-gray-600 mt-2">{error}</p>
        </div>
      </div>
    );
  }

  const avgScore = stats?.average_scores?.avg_score || 0;
  const avgRisk = stats?.average_scores?.avg_risk || 0;
  const totalAudits = stats?.total_audits || 0;

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900">Security Dashboard</h1>
        <p className="text-gray-600 mt-1">Advanced analytics and visualizations</p>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <MetricCard
          icon={<FileText className="h-6 w-6 text-blue-600" />}
          label="Total Audits"
          value={totalAudits}
        />
        <MetricCard
          icon={<TrendingUp className="h-6 w-6 text-green-600" />}
          label="Avg Security Score"
          value={`${Math.round(avgScore)}%`}
          trend="positive"
        />
        <MetricCard
          icon={<AlertTriangle className="h-6 w-6 text-yellow-600" />}
          label="Avg Risk Score"
          value={`${Math.round(avgRisk)}%`}
          trend="negative"
        />
        <MetricCard
          icon={<Shield className="h-6 w-6 text-purple-600" />}
          label="Critical Vulns"
          value={stats?.top_vulnerabilities?.[0]?.count || 0}
        />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        <ChartCard title="Risk Score Distribution" subtitle="Distribution of audit risk scores">
          <svg ref={riskChartRef} width="350" height="250" className="w-full h-auto" />
        </ChartCard>
        <ChartCard title="Security Score Gauge" subtitle="Average security vs risk score">
          <svg ref={scoreChartRef} width="350" height="250" className="w-full h-auto" />
        </ChartCard>
        <ChartCard title="Top Vulnerabilities" subtitle="Most common security issues">
          <svg ref={vulnChartRef} width="350" height="250" className="w-full h-auto" />
        </ChartCard>
      </div>

      {/* Recent Audits Table */}
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
                  <th className="text-left py-3 px-4 text-sm font-medium text-gray-600">Security Score</th>
                  <th className="text-left py-3 px-4 text-sm font-medium text-gray-600">Risk Score</th>
                  <th className="text-left py-3 px-4 text-sm font-medium text-gray-600">Date</th>
                </tr>
              </thead>
              <tbody>
                {recentAudits.map((audit) => (
                  <tr key={audit.id} className="border-b border-gray-100 hover:bg-gray-50">
                    <td className="py-3 px-4">
                      <span className="text-primary-600 hover:text-primary-700 font-medium">{audit.domain}</span>
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
                    <td className="py-3 px-4">
                      <RiskBadge score={audit.risk_score} />
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

function MetricCard({ icon, label, value, trend }: { 
  icon: React.ReactNode; 
  label: string; 
  value: string | number; 
  trend?: 'positive' | 'negative';
}) {
  return (
    <div className="card">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-600">{label}</p>
          <p className="text-2xl font-bold text-gray-900 mt-1">{value}</p>
        </div>
        <div className={`p-3 rounded-full ${trend === 'positive' ? 'bg-green-100 text-green-600' : trend === 'negative' ? 'bg-red-100 text-red-600' : 'bg-primary-100 text-primary-600'}`}>
          {icon}
        </div>
      </div>
    </div>
  );
}

function ChartCard({ title, subtitle, children }: { 
  title: string; 
  subtitle: string; 
  children: React.ReactNode;
}) {
  return (
    <div className="card">
      <div className="mb-4">
        <h3 className="text-lg font-semibold text-gray-900">{title}</h3>
        <p className="text-sm text-gray-500">{subtitle}</p>
      </div>
      <div className="flex justify-center">
        {children}
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

function RiskBadge({ score }: { score: number }) {
  const color = score >= 70 ? 'text-red-600' : score >= 40 ? 'text-yellow-600' : 'text-green-600';
  return <span className={`font-semibold ${color}`}>{score}%</span>;
}

// Import d3 dynamically
import * as d3 from 'd3';