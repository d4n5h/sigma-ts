export function listOfStrings(raw: any): string[] {
    if (typeof raw === 'undefined' || raw === null) {
        return [];
    }
    if (typeof raw === 'string') {
        return [raw];
    }
    if (Array.isArray(raw)) {
        // Ensure all items are strings. The Go implementation appears to expect this.
        if (raw.every(item => typeof item === 'string')) {
            return raw;
        }
        return [];
    }
    // The Go implementation throws an error for other types.
    // For now, returning an empty array might be safer.
    return [];
} 