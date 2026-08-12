import type { ScanResult } from "../models/ScanResult";
import type {
  RemediationAnalysisOptions,
  RemediationAnalysisResult,
} from "./RemediationModels";

/** A local, deterministic projection over stored scan data. */
export interface RemediationAnalysisSource {
  analyze(
    scanResults: readonly ScanResult[],
    options?: RemediationAnalysisOptions,
  ): RemediationAnalysisResult;
}
