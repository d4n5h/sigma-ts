import type {
    Expr,
    LogEntry,
    MatchOptions,
} from "./types";
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

export class NamedExpr implements Expr {
    name: string;
    x: Expr;

    constructor(name: string, x: Expr) {
        this.name = name;
        this.x = x;
    }

    exprMatches(entry: LogEntry, opts?: MatchOptions): boolean {
        return this.x.exprMatches(entry, opts);
    }
}

export class NotExpr implements Expr {
    x: Expr;

    constructor(x: Expr) {
        this.x = x;
    }

    exprMatches(entry: LogEntry, opts?: MatchOptions): boolean {
        return !this.x.exprMatches(entry, opts);
    }
}

export class AndExpr implements Expr {
    x: Expr[];

    constructor(x: Expr[]) {
        this.x = x;
    }

    exprMatches(entry: LogEntry, opts?: MatchOptions): boolean {
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
    _compiledCache: any;

    constructor(field: string | undefined, modifiers: string[], patterns: string[]) {
        this.field = field;
        this.modifiers = modifiers;
        this.patterns = patterns;
    }

    validate(): Error | null {
        if (this.patterns.length === 0) {
            return new Error("no patterns");
        }

        let patternType: 'glob' | 're' | 'cidr' = 'glob';
        let expand = false;

        for (let i = 0; i < this.modifiers.length; i++) {
            const mod = this.modifiers[i]!;
            switch (mod) {
                case "re": patternType = 're'; break;
                case "cidr": patternType = 'cidr'; break;
                case "contains": case "all": case "startswith": case "endswith": case "windash": case "base64": case "base64offset": break;
                case "expand":
                    expand = true;
                    if (i !== 0) {
                        return new Error("expand can only be the first modifier");
                    }
                    for (const placeholder of this.patterns) {
                        if (!placeholder.startsWith('%') || !placeholder.endsWith('%')) {
                            return new Error(`placeholder "${placeholder}" must start and end with '%'`);
                        }
                    }
                    break;
                default: return new Error(`unknown modifier "${mod}"`);
            }
        }

        if (!expand) {
            if (patternType === 're') {
                for (const pat of this.patterns) {
                    try { new RegExp(pat); } catch (e: any) { return new Error(`pattern ${pat}: ${e.message}`); }
                }
            } else if (patternType === 'cidr') {
                for (const pat of this.patterns) {
                    try { new Address4(pat); } catch (e) {
                        try { new Address6(pat); } catch (e2) { return new Error(`pattern ${pat}: not a valid CIDR`); }
                    }
                }
            }
        }

        return null;
    }

    exprMatches(entry: LogEntry, opts?: MatchOptions): boolean {
        if (this.validate()) {
            return false;
        }

        let fieldContent = "";
        if (!this.field) {
            fieldContent = entry.message;
        } else {
            const lowerCaseField = this.field.toLowerCase();
            for (const key in entry.fields) {
                if (key.toLowerCase() === lowerCaseField) {
                    fieldContent = entry.fields[key]!;
                    break;
                }
            }
        }

        const patterns = this._expandPatterns(opts?.placeholders);
        if (patterns.length === 0) {
            return false;
        }

        const compiled = this._compile(patterns);
        return compiled.matches(fieldContent);
    }

    _expandPatterns(placeholders?: Record<string, string[]>): string[] {
        if (this.modifiers.includes("expand")) {
            let patterns: string[] = [];
            for (const placeholder of this.patterns) {
                const name = placeholder.substring(1, placeholder.length - 1);
                if (placeholders && placeholders[name]) {
                    patterns = patterns.concat(placeholders[name]!);
                }
            }
            return patterns;
        }
        return this.patterns;
    }

    _compile(patterns: string[]): { matches: (s: string) => boolean } {
        const cacheKey = JSON.stringify({ patterns, modifiers: this.modifiers, field: this.field });
        if (this._compiledCache && this._compiledCache.key === cacheKey) {
            return this._compiledCache.compiled;
        }

        let compiled: { matches: (s: string) => boolean };

        if (this.modifiers.includes("cidr")) {
            const cidrMatchers = patterns.map(p => {
                try { return new Address4(p); } catch (e) { /* ignore */ }
                try { return new Address6(p); } catch (e) { /* ignore */ }
                return null;
            }).filter((c): c is (Address4 | Address6) => c !== null);

            compiled = {
                matches: (s: string) => {
                    try {
                        const addr = new Address4(s);
                        return cidrMatchers.some(c => c instanceof Address4 && (addr.isInSubnet(c as Address4)));
                    } catch (e) {
                        try {
                            const addr = new Address6(s);
                            return cidrMatchers.some(c => c instanceof Address6 && (addr.isInSubnet(c as Address6)));
                        } catch (e2) {
                            return false;
                        }
                    }
                }
            };
        } else {
            const regexes: RegExp[] = [];
            const processPattern = (pattern: string) => {
                if (this.modifiers.includes("re")) {
                    return `(?:${pattern})`;
                }
                if (this.modifiers.includes("base64offset")) {
                    return `(?:${Array.from(base64Permute(pattern)).join('|')})`;
                }

                let p = this.modifiers.includes("base64") ? Buffer.from(pattern).toString('base64') : pattern;

                if (this.modifiers.includes("windash")) {
                    p = `(?:${Array.from(windashPermute(p)).map(escapeRegex).join('|')})`;
                } else {
                    p = escapeRegex(p).replace(/\\\*/g, '.*').replace(/\\\?/g, '.');
                }

                const contains = this.modifiers.includes("contains");
                let prefix = (!this.field || contains || this.modifiers.includes("endswith")) ? "" : "^";
                let suffix = (!this.field || contains || this.modifiers.includes("startswith")) ? "" : "$";

                return `${prefix}(?:${p})${suffix}`;
            };

            if (this.modifiers.includes("all")) {
                for (const pat of patterns) {
                    regexes.push(new RegExp(processPattern(pat), 'i'));
                }
                compiled = {
                    matches: (s: string) => regexes.every(r => r.test(s))
                };
            } else {
                const combined = patterns.map(processPattern).join('|');
                regexes.push(new RegExp(combined, 'i'));
                compiled = {
                    matches: (s: string) => regexes[0]!.test(s)
                };
            }
        }

        this._compiledCache = { key: cacheKey, compiled };
        return compiled;
    }
} 