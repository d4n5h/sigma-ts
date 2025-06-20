# sigmalite-ts

[![Tests](https://github.com/d4n5h/sigmalite-ts/actions/workflows/test.yml/badge.svg)](https://github.com/d4n5h/sigmalite-ts/actions/workflows/test.yml)

Package `sigmalite-ts` is a TypeScript port of the Go library [`github.com/runreveal/sigmalite`][sigmalite-go].
It provides a parser and an execution engine for the [Sigma detection format][sigma-format].

## Install

```shell
bun add @d4n5h/sigmalite-ts
```
Or with npm:
```shell
npm install @d4n5h/sigmalite-ts
```
Or with yarn:
```shell
yarn add @d4n5h/sigmalite-ts
```

## Usage

Here's a basic example of how to parse a rule and match it against a log entry:

```typescript
import { parseRule, type LogEntry } from "sigmalite-ts";

const ruleYaml = `
title: My example rule
detection:
  keywords:
    - foo
    - bar
  selection:
    EventId: 1234
  condition: keywords and selection
`;

try {
    const rule = parseRule(ruleYaml);

    const logEntry: LogEntry = {
        message: "Hello foo",
        fields: {
            "EventId": "1234",
        },
    };

    const isMatch = rule.detection.expr.exprMatches(logEntry);

    console.log(`Rule "${rule.title}" matches: ${isMatch}`);
    //> Rule "My example rule" matches: true

} catch (e) {
    if (e instanceof Error) {
        console.error("Error:", e.message);
    }
}
```

[sigmalite-go]: https://github.com/runreveal/sigmalite
[sigma-format]: https://sigmahq.io/

## Rules

Rules are written in [YAML][] format and, at a minimum, must include a `title` and a `detection` block.

```yaml
title: My example rule
detection:
  keywords:
    - foo
    - bar
  selection:
    EventId: 1234
  condition: keywords and selection
```

The `condition` field in the `detection` block is a logical expression that joins other field selectors in the `detection` block. In this example, the rule will match any log entry that has an `EventId` field that is exactly `1234` _and_ has "foo" _or_ "bar" in its message.

Fields can also be matched using regular expressions:

```yaml
title: My example rule with a timestamp
detection:
  selection:
    Timestamp|re: ^2024-06-01T(01|02|03):[0-5][0-9]:[0-5][0-9]$
  condition: selection
```

As well as [CIDRs][CIDR]:

```yaml
title: My example rule with IP addresses
detection:
  local:
    DestinationIp|cidr:
      - '127.0.0.0/8'
      - '10.0.0.0/8'
      - '172.16.0.0/12'
      - '192.168.0.0/16'
  condition: not local
```

More information can be found in the [official Sigma rules documentation][sigma-rules-docs].

[CIDR]: https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing
[sigma-rules-docs]: https://sigmahq.io/docs/basics/rules.html
[YAML]: https://yaml.org/

### Field Modifiers

This library supports the following [field modifiers][sigma-modifiers]:

-   [`all`](https://sigmahq.io/docs/basics/modifiers.html#all)
-   [`base64`](https://sigmahq.io/docs/basics/modifiers.html#base64-base64offset)
-   [`base64offset`](https://sigmahq.io/docs/basics/modifiers.html#base64-base64offset)
-   [`cidr`](https://sigmahq.io/docs/basics/modifiers.html#cidr)
-   [`contains`](https://sigmahq.io/docs/basics/modifiers.html#contains)
-   [`endswith`](https://sigmahq.io/docs/basics/modifiers.html#endswith)
-   [`expand`](https://sigmahq.io/docs/basics/modifiers.html#expand)
-   [`re`](https://sigmahq.io/docs/basics/modifiers.html#re)
-   [`startswith`](https://sigmahq.io/docs/basics/modifiers.html#startswith)
-   [`windash`](https://sigmahq.io/docs/basics/modifiers.html#windash)

[sigma-modifiers]: https://sigmahq.io/docs/basics/modifiers.html

## API

### `parseRule(ruleYaml: string): Rule`
Parses a YAML string containing a Sigma rule and returns a `Rule` object. Throws a `SigmaError` if parsing fails.

### `Rule`
An interface representing a parsed Sigma rule. It contains properties like `title`, `description`, `detection`, etc.

### `LogEntry`
An interface for log entries to be matched against a rule.
```typescript
interface LogEntry {
    message: string;
    fields: Record<string, string>;
}
```

### `rule.detection.expr.exprMatches(entry: LogEntry): boolean`
The core matching function. It evaluates the rule's detection logic against the provided `LogEntry` and returns `true` if it matches, otherwise `false`.

## License

This library is a TypeScript port of [`github.com/runreveal/sigmalite`][sigmalite-go], which is licensed under the [Apache 2.0 License](https://github.com/runreveal/sigmalite/blob/main/LICENSE).
