/**
 * Local-only timeline storage for audit results. Stored as a JSON file under
 *   $SAFE_WEB_AUDIT_HOME (default: ~/.safe-web-audit/history.json)
 *
 * No data ever leaves the host. Reports are stored *after* redaction.
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import os from "node:os";

import type { AuditReport } from "./audit.js";

export interface HistoryEntry {
  timestamp: string;
  target_url: string;
  final_url: string | null;
  status: number | null;
  risk_summary: AuditReport["risk_summary"];
  finding_codes: string[];
  site_type?: string;
}

export interface ComparisonResult {
  baseline_timestamp: string;
  latest_timestamp: string;
  resolved: string[]; // codes present in baseline but not latest
  introduced: string[]; // codes in latest but not baseline
  unchanged: string[];
  baseline_risk: AuditReport["risk_summary"];
  latest_risk: AuditReport["risk_summary"];
}

function homeDir(): string {
  return process.env.SAFE_WEB_AUDIT_HOME || path.join(os.homedir(), ".safe-web-audit");
}

function historyFile(): string {
  return path.join(homeDir(), "history.json");
}

async function readAll(): Promise<HistoryEntry[]> {
  try {
    const raw = await fs.readFile(historyFile(), "utf8");
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as HistoryEntry[]) : [];
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException)?.code === "ENOENT") return [];
    return [];
  }
}

async function writeAll(entries: HistoryEntry[]): Promise<void> {
  await fs.mkdir(homeDir(), { recursive: true });
  await fs.writeFile(historyFile(), JSON.stringify(entries, null, 2), "utf8");
}

export async function saveAudit(report: AuditReport, siteType?: string): Promise<HistoryEntry> {
  const entry: HistoryEntry = {
    timestamp: new Date().toISOString(),
    target_url: report.target_url,
    final_url: report.final_url,
    status: report.status,
    risk_summary: report.risk_summary,
    finding_codes: report.findings.map((f) => f.code).filter(Boolean) as string[],
    site_type: siteType,
  };
  const entries = await readAll();
  entries.push(entry);
  // Cap to 500 most-recent entries to keep file small.
  const trimmed = entries.slice(-500);
  await writeAll(trimmed);
  return entry;
}

export async function listHistory(target?: string): Promise<HistoryEntry[]> {
  const entries = await readAll();
  if (!target) return entries;
  // Match by target_url or hostname.
  let host: string | null = null;
  try {
    host = new URL(target).hostname;
  } catch {
    /* ignore */
  }
  return entries.filter((e) => {
    if (e.target_url === target) return true;
    if (host) {
      try {
        return new URL(e.target_url).hostname === host;
      } catch {
        return false;
      }
    }
    return false;
  });
}

export async function compareLatest(target: string): Promise<ComparisonResult | null> {
  const entries = await listHistory(target);
  if (entries.length < 2) return null;
  const latest = entries[entries.length - 1];
  const baseline = entries[entries.length - 2];
  return diff(baseline, latest);
}

export function diff(baseline: HistoryEntry, latest: HistoryEntry): ComparisonResult {
  const baseSet = new Set(baseline.finding_codes);
  const latestSet = new Set(latest.finding_codes);
  return {
    baseline_timestamp: baseline.timestamp,
    latest_timestamp: latest.timestamp,
    resolved: [...baseSet].filter((c) => !latestSet.has(c)),
    introduced: [...latestSet].filter((c) => !baseSet.has(c)),
    unchanged: [...latestSet].filter((c) => baseSet.has(c)),
    baseline_risk: baseline.risk_summary,
    latest_risk: latest.risk_summary,
  };
}
