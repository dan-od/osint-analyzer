import { AnalysisType, ValidationResult, RiskLevel } from '@/types';
import { parseIp } from './ip';
import { riskLevelFor } from './scoring-rules';

// Input validation functions
export function validateInput(input: string): ValidationResult {
  const trimmed = input.trim();
  
  if (!trimmed) {
    return { isValid: false, type: null, normalizedInput: '', error: 'Please enter a value to analyze' };
  }

  // Check for IP address first – dotted IPv4 would otherwise match the phone pattern
  const ip = parseIp(trimmed);
  if (ip) {
    return { isValid: true, type: 'ip', normalizedInput: ip.address };
  }

  // Check for email
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (emailRegex.test(trimmed)) {
    return { isValid: true, type: 'email', normalizedInput: trimmed.toLowerCase() };
  }

  // Check for phone number (international format)
  const phoneRegex = /^[\+]?[(]?[0-9]{1,3}[)]?[-\s\.]?[(]?[0-9]{1,4}[)]?[-\s\.]?[0-9]{1,4}[-\s\.]?[0-9]{1,9}$/;
  const cleanedPhone = trimmed.replace(/[\s\-\.\(\)]/g, '');
  if (phoneRegex.test(trimmed) || (cleanedPhone.length >= 10 && cleanedPhone.length <= 15 && /^\+?\d+$/.test(cleanedPhone))) {
    return { isValid: true, type: 'phone', normalizedInput: cleanedPhone };
  }

  // Check for crypto wallet (Bitcoin, Ethereum)
  const btcRegex = /^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$/;
  const ethRegex = /^0x[a-fA-F0-9]{40}$/;
  if (btcRegex.test(trimmed) || ethRegex.test(trimmed)) {
    return { isValid: true, type: 'crypto', normalizedInput: trimmed };
  }

  // Check for domain
  const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  if (domainRegex.test(trimmed)) {
    return { isValid: true, type: 'domain', normalizedInput: trimmed.toLowerCase() };
  }

  // Try to extract domain from URL
  try {
    const url = new URL(trimmed.startsWith('http') ? trimmed : `https://${trimmed}`);
    const domain = url.hostname;
    if (domainRegex.test(domain)) {
      return { isValid: true, type: 'domain', normalizedInput: domain };
    }
  } catch {
    // Not a valid URL
  }

  return { 
    isValid: false, 
    type: null, 
    normalizedInput: trimmed, 
    error: 'Could not detect input type. Please enter a valid email, domain, IP address, phone number, or crypto wallet address.' 
  };
}

// Calculate risk level from score
export function getRiskLevel(score: number): RiskLevel {
  return riskLevelFor(score);
}

// Get risk color class
export function getRiskColor(level: RiskLevel): string {
  switch (level) {
    case 'low': return 'text-risk-low';
    case 'medium': return 'text-risk-medium';
    case 'high': return 'text-risk-high';
    case 'critical': return 'text-risk-critical';
  }
}

export function getRiskBgColor(level: RiskLevel): string {
  switch (level) {
    case 'low': return 'bg-risk-low/20 border-risk-low/50';
    case 'medium': return 'bg-risk-medium/20 border-risk-medium/50';
    case 'high': return 'bg-risk-high/20 border-risk-high/50';
    case 'critical': return 'bg-risk-critical/20 border-risk-critical/50';
  }
}

// Get icon for analysis type
export function getAnalysisTypeIcon(type: AnalysisType): string {
  switch (type) {
    case 'email': return '📧';
    case 'domain': return '🌐';
    case 'phone': return '📱';
    case 'crypto': return '₿';
    case 'ip': return '🖥️';
  }
}

// Format timestamp
export function formatTimestamp(timestamp: string): string {
  return new Date(timestamp).toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

// Generate random delay for simulated loading
export function randomDelay(min: number = 500, max: number = 1500): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

// Truncate string
export function truncate(str: string, length: number): string {
  if (str.length <= length) return str;
  return str.slice(0, length) + '...';
}

// Class name helper
export function cn(...classes: (string | boolean | undefined | null)[]): string {
  return classes.filter(Boolean).join(' ');
}
