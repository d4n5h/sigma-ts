import { SigmaDate } from "./date";
import { Address4, Address6 } from 'ip-address';

// --- Utility functions for evaluation ---

function escapeRegex(s: string): string {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function* windashPermute(input: string): Generator<string> {
    const windowsParamDashes = ['-', '/', '–', '—', '―'];
    const regex = /\B[-/]\b/;
    for (const dash of windowsParamDashes) {
        yield input.replace(regex, dash);
    }
}

function* base64Permute(input: string): Generator<string> {
    if (input.length === 0) return;
    const inputBytes = Buffer.from(input);

    for (let i = 0; i < 3; i++) {
        const shifted = Buffer.concat([Buffer.alloc(i, ' '), inputBytes]);
        const encoded = shifted.toString('base64');
        const startOffset = [0, 2, 3][i]!;
        const endOffset = [0, -3, -2][(inputBytes.length + i) % 3]!;
        yield encoded.substring(startOffset, encoded.length + endOffset);
    }
}

// From sigma.go

export type Status = "stable" | "test" | "experimental" | "deprecated" | "unsupported";

export type Level = "informational" | "low" | "medium" | "high" | "critical";

export type RelationType = "derived" | "obsoletes" | "merged" | "renamed" | "similar";

export interface Relation {
    id: string;
    type: RelationType;
}

export interface LogSource {
    category?: string;
    product?: string;
    service?: string;
    definition?: string;
}

export interface Rule {
    title: string;
    id?: string;
    related?: Relation[];
    status?: Status;
    description?: string;
    references?: string[];
    author?: string;
    date?: SigmaDate;
    modified?: SigmaDate;
    tags?: string[];
    level?: Level;
    logsource?: LogSource;
    detection: Detection;
    fields?: string[];
    falsepositives?: string[];
    extra?: Record<string, any>;
}

export interface Detection {
    expr: Expr;
}

export interface LogEntry {
    message: string;
    fields: Record<string, string>;
}

export interface DetectionInput {
    product?: string;
    service?: string;
    category?: string;
    logEntry: LogEntry;
}

export type DetectionQuery = Record<string, string>;

export interface MatchOptions {
    placeholders?: Record<string, string[]>;
}

export interface Expr {
    exprMatches(entry: LogEntry, opts?: MatchOptions): boolean;
} 