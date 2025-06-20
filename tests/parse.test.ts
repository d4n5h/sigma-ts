import { test, expect } from "@jest/globals";
import * as fs from "fs";
import * as path from "path";
import { type Rule, SigmaDate, parseRule, AndExpr, OrExpr, NotExpr, NamedExpr, SearchAtom } from "../src/";

const testDataDir = path.join("tests", "testdata");

interface TestCase {
    filename: string;
    want: Partial<Rule>;
}

const testCases: TestCase[] = [
    {
        filename: "sigma/whoami.yml",
        want: {
            title: "Whoami Execution",
            description: "Detects a whoami.exe execution",
            references: [
                "https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment",
            ],
            author: "Florian Roth",
            date: new SigmaDate(2019, 10, 23),
            logsource: {
                category: "process_creation",
                product: "windows",
            },
            detection: {
                expr: new NamedExpr(
                    "selection",
                    new SearchAtom(
                        "Image",
                        [],
                        ["C:\\Windows\\System32\\whoami.exe"]
                    )
                ),
            },
            level: "high",
        },
    },
    {
        filename: "sigma/aws_cloudtrail_disable_logging.yml",
        want: {
            title: "AWS CloudTrail Important Change",
            id: "4db60cc0-36fb-42b7-9b58-a5b53019fb74",
            status: "test",
            description: "Detects disabling, deleting and updating of a Trail",
            references: [
                "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html",
            ],
            author: "vitaliy0x1",
            date: new SigmaDate(2020, 1, 21),
            modified: new SigmaDate(2022, 10, 9),
            tags: ["attack.defense_evasion", "attack.t1562.001"],
            logsource: { product: "aws", service: "cloudtrail" },
            detection: {
                expr: new NamedExpr("selection_source", new AndExpr([
                    new SearchAtom("eventSource", [], ["cloudtrail.amazonaws.com"]),
                    new SearchAtom("eventName", [], ["StopLogging", "UpdateTrail", "DeleteTrail"]),
                ])),
            },
            falsepositives: ["Valid change in a Trail"],
            level: "medium",
        },
    },
    {
        filename: "sigma/lnx_buffer_overflows.yml",
        want: {
            title: "Buffer Overflow Attempts",
            id: "18b042f0-2ecd-4b6e-9f8d-aa7a7e7de781",
            status: "stable",
            description: "Detects buffer overflow attempts in Unix system log files",
            references: ["https://github.com/ossec/ossec-hids/blob/1ecffb1b884607cb12e619f9ab3c04f530801083/etc/rules/attack_rules.xml"],
            author: "Florian Roth (Nextron Systems)",
            date: new SigmaDate(2017, 3, 1),
            tags: ["attack.t1068", "attack.privilege_escalation"],
            logsource: { product: "linux" },
            detection: {
                expr: new NamedExpr("keywords", new SearchAtom(undefined, [], [
                    "attempt to execute code on stack by",
                    "FTP LOGIN FROM .* 0bin0sh",
                    "rpc.statd[\\d+]: gethostbyname error for",
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                ])),
            },
            falsepositives: ["Unknown"],
            level: "high",
        },
    },
    {
        filename: "mixed_detection.yml",
        want: {
            title: "Mixed Detection List Example",
            description: "A contrived example for mixing lists of string matches with field matches",
            logsource: { product: "windows" },
            detection: {
                expr: new NamedExpr("selection", new OrExpr([
                    new SearchAtom(undefined, [], ["EVILSERVICE"]),
                    new SearchAtom("Image", ["endswith"], ["\\\\example.exe"]),
                ])),
            },
        },
    },
    {
        filename: "condition_list.yml",
        want: {
            title: "Condition List Example",
            description: "A contrived example for using a list of conditions.",
            logsource: { product: "windows" },
            detection: {
                expr: new OrExpr([
                    new NamedExpr("selection1", new SearchAtom("Image", ["endswith"], ["\\\\example.exe"])),
                    new NamedExpr("selection2", new SearchAtom("Image", ["endswith"], ["\\\\evil.exe"])),
                ]),
            },
        },
    },
    {
        filename: "sigma/file_access_win_browser_credential_access.yml",
        want: {
            title: "Access To Browser Credential Files By Uncommon Application",
            id: "91cb43db-302a-47e3-b3c8-7ede481e27bf",
            status: "experimental",
            logsource: {
                category: "file_access",
                product: "windows",
                definition: "Requirements: Microsoft-Windows-Kernel-File ETW provider",
            },
            detection: {
                expr: new AndExpr([
                    new OrExpr([
                        new NamedExpr("selection_chromium", new SearchAtom("FileName", ["contains"], [
                            "\\Appdata\\Local\\Chrome\\User Data\\Default\\Login Data",
                            "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies",
                            "\\AppData\\Local\\Google\\Chrome\\User Data\\Local State",
                        ])),
                        new NamedExpr("selection_firefox", new SearchAtom("FileName", ["endswith"], [
                            "\\cookies.sqlite",
                            "release\\key3.db",
                            "release\\key4.db",
                            "release\\logins.json",
                        ])),
                        new NamedExpr("selection_ie", new SearchAtom("FileName", ["endswith"], ["\\Appdata\\Local\\Microsoft\\Windows\\WebCache\\WebCacheV01.dat"])),
                    ]),
                    new NotExpr(new OrExpr([
                        new NamedExpr("filter_main_generic", new SearchAtom("Image", ["contains"], [
                            ":\\Program Files (x86)\\",
                            ":\\Program Files\\",
                            ":\\Windows\\system32\\",
                            ":\\Windows\\SysWOW64\\",
                        ])),
                        new NamedExpr("filter_main_system", new SearchAtom("Image", [], ["System"])),
                    ])),
                    new NotExpr(new OrExpr([
                        new NamedExpr("filter_optional_defender", new AndExpr([
                            new SearchAtom("Image", ["contains"], [":\\ProgramData\\Microsoft\\Windows Defender\\"]),
                            new SearchAtom("Image", ["endswith"], ["\\MpCopyAccelerator.exe", "\\MsMpEng.exe"]),
                        ])),
                        new NamedExpr("filter_optional_thor", new SearchAtom("Image", ["endswith"], ["\\thor64.exe", "\\thor.exe"])),
                    ])),
                ]),
            },
        },
    },
];

// Helper to deeply compare expression trees, since class instances are not deeply equal by default.
function expectExpr(got: any, want: any) {
    expect(got.constructor.name).toBe(want.constructor.name);

    if (got instanceof SearchAtom) {
        expect(got.field).toEqual(want.field);
        expect(got.modifiers).toEqual(want.modifiers);
        expect(got.patterns).toEqual(want.patterns);
    } else if (got instanceof NamedExpr) {
        expect(got.name).toEqual(want.name);
        expectExpr(got.x, want.x);
    } else if (got instanceof NotExpr) {
        expectExpr(got.x, want.x);
    } else if (got instanceof AndExpr || got instanceof OrExpr) {
        expect(got.x.length).toEqual(want.x.length);
        for (let i = 0; i < got.x.length; i++) {
            expectExpr(got.x[i], want.x[i]);
        }
    }
}

for (const tc of testCases) {
    test(`Parse rule test for ${tc.filename}`, () => {
        const filePath = path.join(testDataDir, tc.filename);
        const fileContent = fs.readFileSync(filePath, "utf-8");
        const got = parseRule(fileContent);

        // Compare detection expression tree separately
        if (tc.want.detection) {
            expectExpr(got.detection.expr, tc.want.detection.expr);
        }

        // Compare the rest of the rule object
        for (const key in tc.want) {
            if (key === 'detection') continue;
            const wantValue = (tc.want as any)[key];
            const gotValue = (got as any)[key];
            if (wantValue instanceof SigmaDate) {
                expect(gotValue.equals(wantValue)).toBe(true);
            } else {
                expect(gotValue).toEqual(wantValue);
            }
        }
    });
} 