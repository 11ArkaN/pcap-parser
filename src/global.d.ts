import type {
  CorrelationJobStatus,
  CorrelationReportV1,
  CorrelationRequest,
  IpLookupData,
  ParsedConnection
} from './types';

type OpenDialogResult = {
  canceled: boolean;
  filePaths: string[];
};

type ReadFileResult =
  | {
      success: true;
      buffer: number[];
      fileName: string;
    }
  | {
      success: false;
      error: string;
    };

type LookupIpResult =
  | {
      success: true;
      data: IpLookupData;
    }
  | {
      success: false;
      error: string;
    };

type ParseFileResult =
  | {
      success: true;
      data: {
        filePath: string;
        fileName: string;
        fileSize: number;
        connections: ParsedConnection[];
        truncated: boolean;
      };
    }
  | {
      success: false;
      error: string;
    };

type CorrelationStartResult =
  | {
      success: true;
      jobId: string;
    }
  | {
      success: false;
      error: string;
    };

type CorrelationStatusResult =
  | {
      success: true;
      status: CorrelationJobStatus;
    }
  | {
      success: false;
      error: string;
    };

type CorrelationResult =
  | {
      success: true;
      data: CorrelationReportV1;
    }
  | {
      success: false;
      error: string;
    };

type CorrelationCancelResult = {
  success: boolean;
  error?: string;
};

declare global {
  interface Window {
    electronAPI: {
      openFileDialog: () => Promise<OpenDialogResult>;
      openProcmonDialog: () => Promise<OpenDialogResult>;
      readFile: (filePath: string) => Promise<ReadFileResult>;
      parseFile: (filePath: string, maxConnections?: number) => Promise<ParseFileResult>;
      lookupIp: (ip: string) => Promise<LookupIpResult>;
      startCorrelation: (payload: CorrelationRequest) => Promise<CorrelationStartResult>;
      getCorrelationStatus: (jobId: string) => Promise<CorrelationStatusResult>;
      cancelCorrelation: (jobId: string) => Promise<CorrelationCancelResult>;
      getCorrelationResult: (jobId: string) => Promise<CorrelationResult>;
    };
  }
}

export {};
