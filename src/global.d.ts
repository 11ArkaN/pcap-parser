import type { IpLookupData } from './types';

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

declare global {
  interface Window {
    electronAPI: {
      openFileDialog: () => Promise<OpenDialogResult>;
      readFile: (filePath: string) => Promise<ReadFileResult>;
      lookupIp: (ip: string) => Promise<LookupIpResult>;
    };
  }
}

export {};
