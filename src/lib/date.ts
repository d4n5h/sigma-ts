export class SigmaDate {
    public year: number; // 1-based
    public month: number; // 1-based
    public day: number; // 1-based

    constructor(year: number, month: number, day: number) {
        const d = new Date(Date.UTC(year, month - 1, day));
        this.year = d.getUTCFullYear();
        this.month = d.getUTCMonth() + 1;
        this.day = d.getUTCDate();
    }

    static parse(s: string): SigmaDate {
        const parts = s.split(/[\/-]/);
        if (parts.length !== 3) {
            throw new Error(`parse sigma date ${s}: unknown format`);
        }
        const year = parseInt(parts[0]!, 10);
        const month = parseInt(parts[1]!, 10);
        const day = parseInt(parts[2]!, 10);

        if (isNaN(year) || isNaN(month) || isNaN(day)) {
            throw new Error(`parse sigma date ${s}: invalid date component`);
        }
        if (year < 100) {
            throw new Error(`parse sigma date ${s}: short years not allowed`);
        }
        if (month < 1 || month > 12) {
            throw new Error(`parse sigma date ${s}: invalid month ${month}`);
        }
        if (day < 1 || day > 31) {
            throw new Error(`parse sigma date ${s}: invalid day ${day}`);
        }

        return new SigmaDate(year, month, day);
    }

    equals(other: SigmaDate): boolean {
        return this.year === other.year && this.month === other.month && this.day === other.day;
    }

    toString(): string {
        const y = this.year.toString().padStart(4, '0');
        const m = this.month.toString().padStart(2, '0');
        const d = this.day.toString().padStart(2, '0');
        return `${y}/${m}/${d}`;
    }
} 