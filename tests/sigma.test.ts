import { test, expect } from "@jest/globals";
import * as fs from "fs";
import * as path from "path";
import { type LogEntry, type MatchOptions, parseRule } from "../src/";

const testDataDir = path.join("tests", "testdata");

interface TestCase {
    filename: string;
    entry: LogEntry;
    options?: MatchOptions;
    want: boolean;
}

const testCases: TestCase[] = [
    {
        filename: "sigma/aws_cloudtrail_disable_logging.yml",
        entry: {
            message: "",
            fields: {
                "eventSource": "cloudtrail.amazonaws.com",
                "eventName": "StopLogging",
            },
        },
        want: true,
    },
    {
        filename: "sigma/aws_cloudtrail_disable_logging.yml",
        entry: {
            message: "",
            fields: {
                "eventSource": "cloudtrail.amazonaws.com",
                "eventName": "StartLogging",
            },
        },
        want: false,
    },
    {
        filename: "sigma/aws_cloudtrail_disable_logging.yml",
        entry: {
            message: "",
            fields: {
                "eventSource": "example.com",
                "eventName": "StopLogging",
            },
        },
        want: false,
    },
    {
        filename: "sigma/aws_cloudtrail_disable_logging.yml",
        entry: {
            message: "",
            fields: {
                "eventSource": "cloudtrail.amazonaws.com",
                "eventName": "StopLoggingOrElse",
            },
        },
        want: false,
    },
    {
        filename: "sigma/lnx_buffer_overflows.yml",
        entry: {
            message: "hello world",
            fields: {},
        },
        want: false,
    },
    {
        filename: "sigma/lnx_buffer_overflows.yml",
        entry: {
            message: "THERE WAS AN ATTEMPT TO EXECUTE CODE ON STACK BY MAIN",
            fields: {},
        },
        want: true,
    },
    {
        filename: "sigma/whoami.yml",
        entry: {
            message: "",
            fields: {
                "Image": "foo",
            },
        },
        want: false,
    },
    {
        filename: "sigma/lnx_auditd_unix_shell_configuration_modification.yml",
        entry: {
            message: "",
            fields: {
                "type": "PATH",
                "name": "/etc/shells",
            },
        },
        want: true,
    },
    {
        filename: "sigma/lnx_auditd_unix_shell_configuration_modification.yml",
        entry: {
            message: "",
            fields: {
                "type": "PATH",
                "name": "/etc/profile.d/01-locale-fix.sh",
            },
        },
        want: true,
    },
    {
        filename: "sigma/lnx_auditd_unix_shell_configuration_modification.yml",
        entry: {
            message: "",
            fields: {
                "type": "PATH",
                "name": "/home/light/.zshrc",
            },
        },
        want: true,
    },
    {
        filename: "sigma/lnx_auditd_unix_shell_configuration_modification.yml",
        entry: {
            message: "",
            fields: {
                "type": "PATH",
                "name": "/var/lib/foo.tmp",
            },
        },
        want: false,
    },
    {
        filename: "sigma/lnx_auditd_coinminer.yml",
        entry: {
            message: "",
            fields: {
                "comm": "echo",
                "a1": "hello",
            },
        },
        want: false,
    },
    {
        filename: "sigma/lnx_auditd_coinminer.yml",
        entry: {
            message: "",
            fields: {
                "comm": "echo",
                "a1": "--cpu-priority=10",
                "a2": "hello",
            },
        },
        want: true,
    },
    {
        filename: "sigma/proxy_ua_susp_base64.yml",
        entry: {
            message: "",
            fields: {
                "c-useragent": "lynx version=1.0",
            },
        },
        want: false,
    },
    {
        filename: "sigma/proxy_ua_susp_base64.yml",
        entry: {
            message: "",
            fields: {
                "c-useragent": "based==",
            },
        },
        want: true,
    },
    {
        filename: "sigma/file_access_win_browser_credential_access.yml",
        entry: {
            message: "",
            fields: {
                "Image": "example.exe",
                "FileName": "C:\\foo.txt",
            },
        },
        want: false,
    },
    {
        filename: "sigma/file_access_win_browser_credential_access.yml",
        entry: {
            message: "",
            fields: {
                "Image": "example.exe",
                "FileName": "C:\\Users\\light\\AppData\\Local\\Chrome\\User Data\\Default\\Login Data",
            },
        },
        want: true,
    },
    {
        filename: "sigma/file_access_win_browser_credential_access.yml",
        entry: {
            message: "",
            fields: {
                "Image": "System",
                "FileName": "C:\\Users\\light\\AppData\\Local\\Chrome\\User Data\\Default\\Login Data",
            },
        },
        want: false,
    },
    {
        filename: "sigma/win_system_susp_service_installation_script.yml",
        entry: {
            message: "",
            fields: {
                "Provider_Name": "Service Control Manager",
                "EventID": "7045",
                "ImagePath": "powershell -c foo",
            },
        },
        want: true,
    },
    {
        filename: "sigma/win_system_susp_service_installation_script.yml",
        entry: {
            message: "",
            fields: {
                "Provider_Name": "Service Control Manager",
                "EventID": "7045",
                "ImagePath": "powershell /c foo",
            },
        },
        want: true,
    },
    {
        filename: "sigma/win_system_susp_service_installation_script.yml",
        entry: {
            message: "",
            fields: {
                "Provider_Name": "Service Control Manager",
                "EventID": "7045",
                "ImagePath": "powershell foo",
            },
        },
        want: false,
    },
    {
        filename: "sigma/win_security_admin_logon.yml",
        entry: {
            message: "",
            fields: {
                "EventID": "4672",
                "SubjectUserSid": "S-1-5-18",
                "SubjectUserName": "AdminMachine",
            },
        },
        options: {
            placeholders: {
                "Admins_Workstations": ["OtherAdminMachine", "AdminMachine"],
            },
        },
        want: false,
    },
    {
        filename: "sigma/win_security_admin_logon.yml",
        entry: {
            message: "",
            fields: {
                "EventID": "4672",
                "SubjectUserSid": "S-1-2-3",
                "SubjectUserName": "AdminMachine",
            },
        },
        options: {
            placeholders: {
                "Admins_Workstations": ["OtherAdminMachine", "AdminMachine"],
            },
        },
        want: false,
    },
    {
        filename: "sigma/win_security_admin_logon.yml",
        entry: {
            message: "",
            fields: {
                "EventID": "4672",
                "SubjectUserSid": "S-1-2-3",
                "SubjectUserName": "UserMachine",
            },
        },
        options: {
            placeholders: {
                "Admins_Workstations": ["OtherAdminMachine", "AdminMachine"],
            },
        },
        want: true,
    },
    {
        filename: "sigma/net_connection_lnx_susp_malware_callback_port.yml",
        entry: {
            message: "",
            fields: {
                "Initiated": "true",
                "DestinationPort": "2222",
                "DestinationIp": "192.0.2.100",
            },
        },
        want: true,
    },
    {
        filename: "sigma/net_connection_lnx_susp_malware_callback_port.yml",
        entry: {
            message: "",
            fields: {
                "Initiated": "true",
                "DestinationPort": "2222",
                "DestinationIp": "127.0.0.1",
            },
        },
        want: false,
    },
];

for (const tc of testCases) {
    test(`Detection test for ${tc.filename}`, () => {
        const filePath = path.join(testDataDir, tc.filename);
        const fileContent = fs.readFileSync(filePath, "utf-8");
        const rule = parseRule(fileContent);

        const got = rule.detection.expr.exprMatches(tc.entry, tc.options);
        expect(got).toBe(tc.want);
    });
} 