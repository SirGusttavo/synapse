import pino, { type DestinationStream, type Logger, type LoggerOptions } from "pino";
import type { LogLevel } from "../../config/schema.js";

const PINO_REDACT_PATHS = [
  "*.password",
  "*.passwd",
  "*.secret",
  "*.token",
  "*.apiKey",
  "*.api_key",
  "*.authorization",
  "*.cookie",
  "*.credential",
  "*.privateKey",
  "password",
  "secret",
  "token",
  "apiKey",
  "authorization",
];

export interface CreateLoggerOptions {
  level?: LogLevel;
  pretty?: boolean;
  destination?: DestinationStream;
}

export function createSynapseLogger(options: CreateLoggerOptions = {}): Logger {
  const level = options.level ?? "info";

  const pinoOptions: LoggerOptions = {
    name: "synapse",
    level,
    redact: {
      paths: PINO_REDACT_PATHS,
      censor: "[REDACTED]",
    },
    timestamp: pino.stdTimeFunctions.isoTime,
  };

  if (options.destination) {
    return pino(pinoOptions, options.destination);
  }

  if (options.pretty) {
    return pino({
      ...pinoOptions,
      transport: {
        target: "pino-pretty",
        options: {
          colorize: true,
          destination: 2,
          translateTime: "SYS:standard",
        },
      },
    });
  }

  // Operational structured logs write to stderr so CLI stdout remains clean and pipeable
  return pino(pinoOptions, pino.destination(2));
}
