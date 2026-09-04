/// <reference types="cypress" />

describe('Dashboard Page', () => {
  beforeEach(() => {
    cy.intercept('GET', '/api/v1/domains', { fixture: 'domains.json' }).as('getDomains');
    cy.intercept('GET', '/api/v1/audits', { fixture: 'audits.json' }).as('getAudits');
    cy.visit('/dashboard');
  });

  it('should load dashboard successfully', () => {
    cy.wait(['@getDomains', '@getAudits']);
    cy.contains('h1', 'Dashboard').should('be.visible');
  });

  it('should display stats cards', () => {
    cy.wait(['@getDomains', '@getAudits']);
    cy.contains('Total Domains').should('be.visible');
    cy.contains('Verified Domains').should('be.visible');
    cy.contains('Total Audits').should('be.visible');
    cy.contains('Average Score').should('be.visible');
  });

  it('should display quick action links', () => {
    cy.wait(['@getDomains', '@getAudits']);
    cy.contains('Add New Domain').should('be.visible');
    cy.contains('View All Audits').should('be.visible');
  });

  it('should navigate to domains page', () => {
    cy.wait(['@getDomains', '@getAudits']);
    cy.contains('Add New Domain').click();
    cy.url().should('include', '/domains');
  });

  it('should navigate to audits page', () => {
    cy.wait(['@getDomains', '@getAudits']);
    cy.contains('View All Audits').click();
    cy.url().should('include', '/audits');
  });
});

describe('Advanced Dashboard Page', () => {
  beforeEach(() => {
    cy.intercept('GET', '/api/v1/mongodb/statistics', { fixture: 'mongodb-stats.json' }).as('getStats');
    cy.intercept('GET', '/api/v1/mongodb/audits/recent*', { fixture: 'recent-audits.json' }).as('getRecentAudits');
    cy.visit('/dashboard/advanced');
  });

  it('should load advanced dashboard', () => {
    cy.wait(['@getStats', '@getRecentAudits']);
    cy.contains('h1', 'Security Dashboard').should('be.visible');
  });

  it('should display metric cards', () => {
    cy.wait(['@getStats', '@getRecentAudits']);
    cy.contains('Total Audits').should('be.visible');
    cy.contains('Avg Security Score').should('be.visible');
    cy.contains('Avg Risk Score').should('be.visible');
    cy.contains('Critical Vulns').should('be.visible');
  });

  it('should display charts', () => {
    cy.wait(['@getStats', '@getRecentAudits']);
    cy.contains('Risk Score Distribution').should('be.visible');
    cy.contains('Security Score Gauge').should('be.visible');
    cy.contains('Top Vulnerabilities').should('be.visible');
  });

  it('should display recent audits table', () => {
    cy.wait(['@getStats', '@getRecentAudits']);
    cy.contains('Recent Audits').should('be.visible');
    cy.get('table').should('be.visible');
  });
});

describe('Domains Page', () => {
  beforeEach(() => {
    cy.intercept('GET', '/api/v1/domains', { fixture: 'domains.json' }).as('getDomains');
    cy.visit('/domains');
  });

  it('should load domains page', () => {
    cy.wait('@getDomains');
    cy.contains('h1', 'Domains').should('be.visible');
  });

  it('should display add domain button', () => {
    cy.wait('@getDomains');
    cy.contains('Add Domain').should('be.visible');
  });

  it('should display domains table', () => {
    cy.wait('@getDomains');
    cy.get('table').should('be.visible');
  });
});

describe('Audits Page', () => {
  beforeEach(() => {
    cy.intercept('GET', '/api/v1/audits', { fixture: 'audits.json' }).as('getAudits');
    cy.visit('/audits');
  });

  it('should load audits page', () => {
    cy.wait('@getAudits');
    cy.contains('h1', 'Audits').should('be.visible');
  });

  it('should display audits table', () => {
    cy.wait('@getAudits');
    cy.get('table').should('be.visible');
  });
});

describe('API Health Check', () => {
  it('should respond to health endpoint', () => {
    cy.request('http://localhost:8012/health').then((response) => {
      expect(response.status).to.eq(200);
      expect(response.body).to.have.property('status', 'healthy');
    });
  });
});