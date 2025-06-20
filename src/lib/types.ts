import { SigmaDate } from "./date";

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

export class NamedExpr implements Expr {
    name: string;
    x: Expr;

    constructor(name: string, x: Expr) {
        this.name = name;
        this.x = x;
    }

    exprMatches(entry: LogEntry, opts?: MatchOptions): boolean {
        // This will be implemented in eval.ts
        return this.x.exprMatches(entry, opts);
    }
}

export class NotExpr implements Expr {
    x: Expr;

    constructor(x: Expr) {
        this.x = x;
    }

    exprMatches(entry: LogEntry, opts?: MatchOptions): boolean {
        // This will be implemented in eval.ts
        return !this.x.exprMatches(entry, opts);
    }
}

export class AndExpr implements Expr {
    x: Expr[];

    constructor(x: Expr[]) {
        this.x = x;
    }

    exprMatches(entry: LogEntry, opts?: MatchOptions): boolean {
        // This will be implemented in eval.ts
        for (const expr of this.x) {
            if (!expr.exprMatches(entry, opts)) {
                return false;
            }
        }
        return true;
    }
}

export class OrExpr implements Expr {
    x: Expr[];

    constructor(x: Expr[]) {
        this.x = x;
    }

    exprMatches(entry: LogEntry, opts?: MatchOptions): boolean {
        // This will be implemented in eval.ts
        for (const expr of this.x) {
            if (expr.exprMatches(entry, opts)) {
                return true;
            }
        }
        return false;
    }
}

export class SearchAtom implements Expr {
    field?: string;
    modifiers: string[];
    patterns: string[];

    constructor(field: string | undefined, modifiers: string[], patterns: string[]) {
        this.field = field;
        this.modifiers = modifiers;
        this.patterns = patterns;
    }

    validate(): Error | null {
        // This will be implemented in eval.ts
        return null;
    }

    exprMatches(entry: LogEntry, opts?: MatchOptions): boolean {
        // This will be implemented in eval.ts
        return false;
    }
} 