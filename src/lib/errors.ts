export class SigmaError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'SigmaError';
    }
}

export class SigmaAggregationNotSupportedError extends SigmaError {
    constructor() {
        super("aggregation expressions not supported");
        this.name = 'SigmaAggregationNotSupportedError';
    }
} 