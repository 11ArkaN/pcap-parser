import type { IpLookupData, ParsedConnection } from './types';

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

declare global {
  interface Window {
    electronAPI: {
      openFileDialog: () => Promise<OpenDialogResult>;
      readFile: (filePath: string) => Promise<ReadFileResult>;
      parseFile: (filePath: string, maxConnections?: number) => Promise<ParseFileResult>;
      lookupIp: (ip: string) => Promise<LookupIpResult>;
    };
  }
}

export {};
