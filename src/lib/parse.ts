import * as YAML from 'yaml';
import type {
  Rule,
  Detection,
  Expr,
  Status,
  Level,
  Relation,
  RelationType,
  LogSource,
} from './types';
import {
  NamedExpr,
  AndExpr,
  OrExpr,
  NotExpr,
  SearchAtom,
} from './eval';
import { SigmaDate } from './date';
import { SigmaError, SigmaAggregationNotSupportedError } from './errors';
import { listOfStrings } from './utils';

// This is an intermediate representation of the rule parsed from YAML
interface YAMLRule {
  title: string;
  id?: string;
  related?: { id: string, type: RelationType }[];
  status?: Status;
  description?: string;
  references?: string[];
  author?: string;
  date?: string;
  modified?: string;
  tags?: string[];
  level?: Level;
  logsource?: LogSource;
  detection: Record<string, any>;
  fields?: string[];
  falsepositives?: any;
  [key: string]: any; // for extra fields
}

const knownTopLevelKeys: Set<string> = new Set([
  "title", "id", "related", "status", "description", "references",
  "author", "date", "modified", "tags", "level", "logsource",
  "detection", "fields", "falsepositives",
]);

export function parseRule(data: string): Rule {
  const doc = YAML.parse(data);

  if (!doc.title) {
    throw new SigmaError("parse sigma rule: missing title");
  }

  const yamlRule: YAMLRule = doc;

  const detection = parseDetection(yamlRule.detection);

  const extra: Record<string, any> = {};
  for (const key in doc) {
    if (!knownTopLevelKeys.has(key)) {
      extra[key] = doc[key];
    }
  }

  let related: Relation[] | undefined;
  if (yamlRule.related) {
    related = [];
    for (let i = 0; i < yamlRule.related.length; i++) {
      const rel = yamlRule.related[i];
      if (!rel) {
        continue;
      }
      if (!rel.id) {
        throw new SigmaError(`parse sigma rule "${yamlRule.title}": related[${i}]: missing id`);
      }
      if (!rel.type) {
        throw new SigmaError(`parse sigma rule "${yamlRule.title}": related[${i}]: missing type`);
      }
      related.push({ id: rel.id, type: rel.type });
    }
  }

  const rule: Rule = {
    title: yamlRule.title,
    id: yamlRule.id,
    related,
    status: yamlRule.status,
    description: yamlRule.description,
    references: yamlRule.references,
    author: yamlRule.author,
    date: yamlRule.date ? SigmaDate.parse(yamlRule.date) : undefined,
    modified: yamlRule.modified ? SigmaDate.parse(yamlRule.modified) : undefined,
    tags: yamlRule.tags,
    level: yamlRule.level,
    logsource: yamlRule.logsource,
    detection,
    fields: yamlRule.fields,
    falsepositives: listOfStrings(yamlRule.falsepositives),
    extra: Object.keys(extra).length > 0 ? extra : undefined,
  };

  return rule;
}

function parseDetection(block: Record<string, any>): Detection {
  if (!block) {
    throw new SigmaError("missing detection");
  }

  const conditions = listOfStrings(block['condition']);
  if (conditions.length === 0) {
    throw new SigmaError("missing detection condition");
  }

  if (block['timeframe']) {
    throw new SigmaAggregationNotSupportedError();
  }

  const identifiers = new Map<string, NamedExpr>();
  const idKeys = Object.keys(block).filter(k => k !== 'condition' && k !== 'timeframe').sort();

  for (const id of idKeys) {
    const value = block[id]!;
    let result: Expr;

    if (Array.isArray(value)) {
      const exprs = value.map(elem => {
        if (typeof elem === 'string') {
          return new SearchAtom(undefined, [], [elem]);
        } else if (typeof elem === 'object' && elem !== null && !Array.isArray(elem)) {
          return parseSearchMap(elem);
        }
        throw new SigmaError(`search identifier "${id}": unsupported list value`);
      });

      if (exprs.length === 1) {
        result = exprs[0]!;
      } else {
        const allAreSearchAtoms = exprs.every(e => e instanceof SearchAtom && !e.field && e.modifiers.length === 0);
        if (allAreSearchAtoms) {
          const patterns = exprs.flatMap(e => (e as SearchAtom).patterns);
          result = new SearchAtom(undefined, [], patterns);
        } else {
          result = new OrExpr(exprs);
        }
      }
    } else if (typeof value === 'object' && value !== null) {
      result = parseSearchMap(value);
    } else if (typeof value === 'string') {
      result = new SearchAtom(undefined, [], [value]);
    } else {
      throw new SigmaError(`search identifier "${id}": unsupported value`);
    }

    const namedExpr = new NamedExpr(id, result);
    identifiers.set(id, namedExpr);
  }

  const container = new OrExpr(
    conditions.map(cond => parseCondition(cond, identifiers))
  );

  let expr: Expr;
  if (container.x.length === 1) {
    expr = container.x[0]!;
  } else {
    expr = container;
  }
  return { expr };
}


function parseSearchMap(node: Record<string, any>): Expr {
  const container = new AndExpr([]);
  for (const key in node) {
    const value = node[key];
    const parts = key.split('|');
    const field = parts[0]!;
    const modifiers = parts.slice(1);

    let patterns: string[];
    if (typeof value === 'string') {
      patterns = [value];
    } else if (typeof value === 'number' || typeof value === 'boolean') {
      patterns = [String(value)];
    } else if (Array.isArray(value) && value.every(v => typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean')) {
      patterns = value.map(String).filter((v): v is string => v !== null && v !== undefined);
    } else {
      throw new SigmaError(`${key}: unsupported value`);
    }

    const atom = new SearchAtom(field, modifiers, patterns);
    const err = atom.validate();
    if (err) {
      throw new SigmaError(`${key}: ${err.message}`);
    }
    container.x.push(atom);
  }

  if (container.x.length === 0) {
    throw new SigmaError("empty map");
  }
  if (container.x.length === 1) {
    return container.x[0]!;
  }
  return container;
}

class ConditionParser {
  private s: string;
  private identifiers: Map<string, NamedExpr>;

  constructor(condition: string, identifiers: Map<string, NamedExpr>) {
    this.s = condition;
    this.identifiers = identifiers;
  }

  lex(): string {
    this.s = this.s.trimStart();
    if (this.s === "") {
      return "";
    }
    const delims = "()|";
    if (this.s[0] && delims.indexOf(this.s[0]) !== -1) {
      const token = this.s[0];
      this.s = this.s.slice(1);
      return token;
    }

    let end = this.s.search(/[()|\s]/);
    if (end === -1) {
      end = this.s.length;
    }
    const token = this.s.substring(0, end);
    this.s = this.s.substring(end);
    return token;
  }

  parse(): Expr {
    const expr = this.expr();
    const tok = this.lex();
    if (tok !== "") {
      throw new SigmaError(`condition: unexpected "${tok}"`);
    }
    return expr;
  }

  private expr(): Expr {
    let x = this.unary();
    return this.binaryTrail(x, 0);
  }

  private unary(): Expr {
    const tok = this.lex();
    if (tok === "") throw new SigmaError("unexpected end of condition");

    if (tok === '(') {
      const x = this.expr();
      const closing = this.lex();
      if (closing !== ')') throw new SigmaError("missing ')'");
      return x;
    }

    if (tok === 'not') {
      const x = this.unary();
      return new NotExpr(x);
    }

    if (tok === '1' || tok === 'all') {
      const of = this.lex();
      if (of !== 'of') throw new SigmaError(`expected "of" after "${tok}"`);
      const pattern = this.lex();
      if (pattern === '') throw new SigmaError(`expected word after "${tok} of"`);

      let filteredIdentifiers: NamedExpr[];
      if (pattern === 'them') {
        filteredIdentifiers = Array.from(this.identifiers.values());
      } else {
        const regex = new RegExp(`^${pattern.replace(/\*/g, '.*')}$`);
        filteredIdentifiers = [];
        for (const [name, expr] of this.identifiers.entries()) {
          if (regex.test(name)) {
            filteredIdentifiers.push(expr);
          }
        }
      }

      if (filteredIdentifiers.length === 0) {
        throw new SigmaError(`${tok} of ${pattern} did not match any identifiers`);
      }
      if (filteredIdentifiers.length === 1) {
        return filteredIdentifiers[0]!;
      }

      if (tok === '1') {
        return new OrExpr(filteredIdentifiers);
      }
      // istanbul ignore else
      if (tok === 'all') {
        return new AndExpr(filteredIdentifiers);
      }
    }

    const identifier = this.identifiers.get(tok);
    if (!identifier) {
      throw new SigmaError(`unknown search identifier ${tok}`);
    }
    return identifier;
  }

  private binaryTrail(x: Expr, minPrecedence: number): Expr {
    while (true) {
      const originalS = this.s;
      const op = this.lex();
      if (op === "") return x;

      if (op === '|') throw new SigmaAggregationNotSupportedError();

      const precedence = this.operatorPrecedence(op);
      if (precedence < minPrecedence) {
        this.s = originalS;
        return x;
      }

      let y = this.unary();

      while (true) {
        const nextOpS = this.s;
        const nextOp = this.lex();
        if (nextOp === "") break;
        this.s = nextOpS; // un-lex

        const nextPrecedence = this.operatorPrecedence(nextOp);
        if (nextPrecedence <= precedence) break;

        y = this.binaryTrail(y, precedence + 1);
      }

      if (op === 'and') {
        if (x instanceof AndExpr) {
          x.x.push(y);
        } else {
          x = new AndExpr([x, y]);
        }
      } else if (op === 'or') {
        if (x instanceof OrExpr) {
          x.x.push(y);
        } else {
          x = new OrExpr([x, y]);
        }
      }
    }
  }

  private operatorPrecedence(tok: string): number {
    if (tok === 'and') return 1;
    if (tok === 'or') return 0;
    return -1;
  }
}

function parseCondition(condition: string, identifiers: Map<string, NamedExpr>): Expr {
  const parser = new ConditionParser(condition, identifiers);
  return parser.parse();
} 