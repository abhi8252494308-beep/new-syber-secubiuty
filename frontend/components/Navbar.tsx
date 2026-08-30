'use client';

import Link from 'next/link';
import { Shield, Menu, X } from 'lucide-react';
import { useState } from 'react';

export default function Navbar() {
  const [isMenuOpen, setIsMenuOpen] = useState(false);

  return (
    <nav className="bg-white border-b border-gray-200 sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between h-16">
          <div className="flex items-center">
            <Link href="/dashboard" className="flex items-center space-x-2">
              <Shield className="h-8 w-8 text-primary-600" />
              <span className="text-xl font-bold text-gray-900">SecureSite Audit</span>
            </Link>
          </div>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center space-x-4">
            <Link href="/dashboard" className="text-gray-700 hover:text-primary-600 px-3 py-2 rounded-md font-medium">
              Dashboard
            </Link>
            <Link href="/domains" className="text-gray-700 hover:text-primary-600 px-3 py-2 rounded-md font-medium">
              Domains
            </Link>
            <Link href="/audits" className="text-gray-700 hover:text-primary-600 px-3 py-2 rounded-md font-medium">
              Audits
            </Link>
            <Link href="/reports" className="text-gray-700 hover:text-primary-600 px-3 py-2 rounded-md font-medium">
              Reports
            </Link>
          </div>

          {/* Mobile menu button */}
          <div className="md:hidden flex items-center">
            <button
              onClick={() => setIsMenuOpen(!isMenuOpen)}
              className="text-gray-700 hover:text-primary-600 p-2"
            >
              {isMenuOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Navigation */}
      {isMenuOpen && (
        <div className="md:hidden border-t border-gray-200 bg-white">
          <div className="px-4 py-3 space-y-2">
            <Link href="/dashboard" className="block text-gray-700 hover:text-primary-600 px-3 py-2 rounded-md font-medium">
              Dashboard
            </Link>
            <Link href="/domains" className="block text-gray-700 hover:text-primary-600 px-3 py-2 rounded-md font-medium">
              Domains
            </Link>
            <Link href="/audits" className="block text-gray-700 hover:text-primary-600 px-3 py-2 rounded-md font-medium">
              Audits
            </Link>
            <Link href="/reports" className="block text-gray-700 hover:text-primary-600 px-3 py-2 rounded-md font-medium">
              Reports
            </Link>
          </div>
        </div>
      )}
    </nav>
  );
}
