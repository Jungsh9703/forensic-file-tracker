import type { Env } from "./env";

export interface IngestConfig {
  maxObjectsPerRun: number;
  maxLinesPerObjectRun: number;
  completedSetCap: number;
  maxDecryptionsPerRun: number;
  httpPrefix: string;
  forensicPrefix: string;
}

export function loadConfig(env: Env): IngestConfig {
  return {
    maxObjectsPerRun: Number(env.MAX_OBJECTS_PER_RUN ?? "5"),
    maxLinesPerObjectRun: Number(env.MAX_LINES_PER_OBJECT_RUN ?? "2000"),
    completedSetCap: Number(env.COMPLETED_SET_CAP ?? "3000"),
    maxDecryptionsPerRun: Number(env.MAX_DECRYPTIONS_PER_RUN ?? "20"),
    httpPrefix: env.HTTP_LOG_PREFIX ?? "http/",
    forensicPrefix: env.FORENSIC_LOG_PREFIX ?? "forensic/",
  };
}
