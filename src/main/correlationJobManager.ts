import { app } from 'electron';
import { spawn } from 'child_process';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { CorrelationJobStatus, CorrelationProgress, CorrelationReportV1, CorrelationRequest } from '../types';

interface RuntimePaths {
  pythonExecutable: string;
  sidecarScript: string;
  procmonExecutable: string | null;
}

interface InternalJob {
  request: CorrelationRequest;
  status: CorrelationJobStatus;
  outputDir: string;
  requestPath: string;
  reportPath: string | null;
  stdoutBuffer: string;
  stderrLineBuffer: string;
  stderrBuffer: string;
  process: ReturnType<typeof spawn> | null;
}

interface StartJobResponse {
  success: true;
  jobId: string;
}

interface FailedJobResponse {
  success: false;
  error: string;
}

type JobResponse = StartJobResponse | FailedJobResponse;

const DEFAULT_PROGRESS: CorrelationProgress = {
  stage: 'prepare',
  current: 0,
  total: 1,
  message: 'Przygotowanie zadania korelacji...'
};

const JOB_ROOT_DIR = 'pcap-analyzer-correlation';
const DEV_PROCMon_CANDIDATES = ['Procmon64.exe', 'Procmon.exe'];
const MAX_DEBUG_ENTRIES = 400;

export class CorrelationJobManager {
  private readonly jobs = new Map<string, InternalJob>();

  startJob(request: CorrelationRequest): JobResponse {
    const validationError = this.validateRequest(request);
    if (validationError) {
      return { success: false, error: validationError };
    }

    const runtime = this.resolveRuntimePaths();
    if (!runtime) {
      return {
        success: false,
        error:
          'Brak runtime do korelacji. Ustaw PCAP_ANALYZER_PYTHON albo dodaj resources/python/python.exe oraz sidecar/job_runner.py.'
      };
    }
    if (!runtime.procmonExecutable) {
      return {
        success: false,
        error:
          'Nie znaleziono Procmon.exe/Procmon64.exe. Dodaj plik do vendor/procmon albo ustaw zmienna PCAP_ANALYZER_PROCMON.'
      };
    }

    const jobId = crypto.randomUUID();
    const outputDir = path.join(os.tmpdir(), JOB_ROOT_DIR, jobId);
    const requestPath = path.join(outputDir, 'request.json');

    fs.mkdirSync(outputDir, { recursive: true });

    const payload = {
      ...request,
      jobId,
      outputDir,
      procmonExecutable: runtime.procmonExecutable,
      createdAt: new Date().toISOString()
    };

    fs.writeFileSync(requestPath, JSON.stringify(payload, null, 2), 'utf-8');

    const status: CorrelationJobStatus = {
      jobId,
      analysisId: request.analysisId,
      state: 'queued',
      progress: DEFAULT_PROGRESS,
      startedAt: new Date().toISOString(),
      lastEventAt: new Date().toISOString(),
      debugEntries: []
    };

    const job: InternalJob = {
      request,
      status,
      outputDir,
      requestPath,
      reportPath: null,
      stdoutBuffer: '',
      stderrLineBuffer: '',
      stderrBuffer: '',
      process: null
    };

    this.jobs.set(jobId, job);
    this.appendDebug(job, 'info', 'Zadanie dodane do kolejki korelacji.', 'prepare');

    const child = spawn(runtime.pythonExecutable, [runtime.sidecarScript, '--request', requestPath], {
      cwd: app.getAppPath(),
      windowsHide: true,
      env: {
        ...process.env,
        PYTHONIOENCODING: 'utf-8'
      }
    });

    job.process = child;
    this.updateStatus(job, { state: 'running', progress: DEFAULT_PROGRESS });
    this.appendDebug(job, 'info', 'Uruchomiono sidecara korelacji.', 'prepare');

    child.stdout.on('data', (chunk: Buffer | string) => {
      const text = typeof chunk === 'string' ? chunk : chunk.toString('utf-8');
      this.consumeStdout(job, text);
    });

    child.stderr.on('data', (chunk: Buffer | string) => {
      const text = typeof chunk === 'string' ? chunk : chunk.toString('utf-8');
      this.consumeStderr(job, text);
    });

    child.on('error', (error) => {
      this.failJob(job, `Nie udalo sie uruchomic sidecara: ${error.message}`);
    });

    child.on('exit', (code, signal) => {
      const latest = this.jobs.get(jobId);
      if (!latest) return;
      latest.process = null;
      this.consumeStdout(latest, '\n');

      if (latest.status.state === 'cancelled' || latest.status.state === 'completed' || latest.status.state === 'failed') {
        return;
      }

      if (code === 0 && latest.reportPath && fs.existsSync(latest.reportPath)) {
        this.updateStatus(latest, {
          state: 'completed',
          progress: {
            stage: 'finalize',
            current: 1,
            total: 1,
            message: 'Korelacja zakonczona.'
          }
        });
        this.appendDebug(latest, 'info', 'Sidecar zakonczyl prace poprawnie.', 'finalize');
        return;
      }

      const stderrSnippet = latest.stderrBuffer.trim().slice(-3000);
      const reason = signal ? `signal ${signal}` : `code ${String(code ?? 'unknown')}`;
      this.failJob(
        latest,
        stderrSnippet
          ? `Sidecar zakonczyl sie z ${reason}. Szczegoly: ${stderrSnippet}`
          : `Sidecar zakonczyl sie z ${reason}.`
      );
    });

    return { success: true, jobId };
  }

  getStatus(jobId: string): CorrelationJobStatus | null {
    const job = this.jobs.get(jobId);
    if (!job) return null;
    return {
      ...job.status,
      progress: { ...job.status.progress },
      debugEntries: [...job.status.debugEntries]
    };
  }

  cancelJob(jobId: string): { success: boolean; error?: string } {
    const job = this.jobs.get(jobId);
    if (!job) {
      return { success: false, error: 'Nie znaleziono zadania.' };
    }

    if (job.status.state === 'completed' || job.status.state === 'failed' || job.status.state === 'cancelled') {
      return { success: true };
    }

    if (job.process && !job.process.killed) {
      job.process.kill();
    }

    this.updateStatus(job, {
      state: 'cancelled',
      progress: {
        stage: job.status.progress.stage,
        current: job.status.progress.current,
        total: job.status.progress.total,
        message: 'Korelacja anulowana.'
      }
    });
    this.appendDebug(job, 'warning', 'Korelacja anulowana przez uzytkownika.', job.status.progress.stage);

    return { success: true };
  }

  getResult(jobId: string): CorrelationReportV1 | null {
    const job = this.jobs.get(jobId);
    if (!job || !job.reportPath || !fs.existsSync(job.reportPath)) {
      return null;
    }

    try {
      const raw = fs.readFileSync(job.reportPath, 'utf-8');
      return JSON.parse(raw) as CorrelationReportV1;
    } catch {
      return null;
    }
  }

  dispose(): void {
    for (const job of this.jobs.values()) {
      if (job.process && !job.process.killed) {
        job.process.kill();
      }
    }
    this.jobs.clear();
  }

  private consumeStdout(job: InternalJob, text: string): void {
    job.stdoutBuffer += text;
    const lines = job.stdoutBuffer.split(/\r?\n/);
    job.stdoutBuffer = lines.pop() ?? '';

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      this.handleEventLine(job, trimmed);
    }
  }

  private consumeStderr(job: InternalJob, text: string): void {
    job.stderrBuffer += text;
    job.stderrLineBuffer += text;
    const lines = job.stderrLineBuffer.split(/\r?\n/);
    job.stderrLineBuffer = lines.pop() ?? '';

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      this.appendDebug(job, 'warning', `stderr: ${trimmed}`, job.status.progress.stage);
    }
  }

  private handleEventLine(job: InternalJob, line: string): void {
    let event: Record<string, unknown>;
    try {
      event = JSON.parse(line) as Record<string, unknown>;
    } catch {
      return;
    }

    const type = typeof event.type === 'string' ? event.type : '';
    if (type === 'progress') {
      const stage = this.normalizeStage(event.stage);
      const current = this.safeNumber(event.current);
      const total = this.safeNumber(event.total);
      const message = typeof event.message === 'string' ? event.message : 'Przetwarzanie...';
      this.updateStatus(job, {
        state: 'running',
        progress: {
          stage,
          current,
          total,
          message
        }
      });
      this.appendDebug(job, 'info', `${message} (${current}/${total || 1})`, stage);
      return;
    }

    if (type === 'warning') {
      const message = typeof event.message === 'string' ? event.message : '';
      if (message) {
        job.stderrBuffer += `\n[warning] ${message}`;
        this.appendDebug(job, 'warning', message, job.status.progress.stage);
      }
      return;
    }

    if (type === 'result') {
      const reportPath = typeof event.report_path === 'string' ? event.report_path : '';
      if (reportPath && fs.existsSync(reportPath)) {
        job.reportPath = reportPath;
        this.appendDebug(job, 'info', `Zapisano raport: ${reportPath}`, 'finalize');
      }
      return;
    }

    if (type === 'error') {
      const message = typeof event.message === 'string' ? event.message : 'Nieznany blad sidecara.';
      this.failJob(job, message);
    }
  }

  private updateStatus(
    job: InternalJob,
    patch: Partial<Pick<CorrelationJobStatus, 'state' | 'progress' | 'error'>>
  ): void {
    if (patch.state && patch.state !== job.status.state) {
      job.status.state = patch.state;
    }

    if (patch.progress) {
      job.status.progress = patch.progress;
    }

    if (patch.error !== undefined) {
      job.status.error = patch.error;
    }

    if (job.status.state === 'completed' || job.status.state === 'failed' || job.status.state === 'cancelled') {
      job.status.endedAt = new Date().toISOString();
    }
  }

  private failJob(job: InternalJob, error: string): void {
    if (job.status.state === 'completed' || job.status.state === 'cancelled' || job.status.state === 'failed') return;
    this.appendDebug(job, 'error', error, job.status.progress.stage);
    this.updateStatus(job, {
      state: 'failed',
      error,
      progress: {
        ...job.status.progress,
        message: 'Korelacja zakonczona bledem.'
      }
    });
  }

  private appendDebug(
    job: InternalJob,
    level: 'info' | 'warning' | 'error',
    message: string,
    stage?: CorrelationProgress['stage']
  ): void {
    const entry = {
      ts: new Date().toISOString(),
      level,
      stage,
      message
    };
    job.status.debugEntries.push(entry);
    if (job.status.debugEntries.length > MAX_DEBUG_ENTRIES) {
      job.status.debugEntries.splice(0, job.status.debugEntries.length - MAX_DEBUG_ENTRIES);
    }
    job.status.lastEventAt = entry.ts;
  }

  private resolveRuntimePaths(): RuntimePaths | null {
    const sidecarCandidates = [
      path.join(process.resourcesPath, 'sidecar', 'job_runner.py'),
      path.join(app.getAppPath(), 'sidecar', 'job_runner.py')
    ];

    const sidecarScript = sidecarCandidates.find((candidate) => fs.existsSync(candidate));
    if (!sidecarScript) {
      return null;
    }

    const pythonCandidates = [
      process.env.PCAP_ANALYZER_PYTHON,
      path.join(process.resourcesPath, 'python', 'python.exe'),
      path.join(app.getAppPath(), 'python', 'python.exe'),
      process.platform === 'win32' ? 'python' : 'python3'
    ].filter((value): value is string => Boolean(value));

    const pythonExecutable =
      pythonCandidates.find((candidate) => this.isExecutableResolvable(candidate)) ??
      (process.platform === 'win32' ? 'python' : 'python3');
    const procmonExecutable = this.resolveProcmonExecutable();

    return {
      pythonExecutable,
      sidecarScript,
      procmonExecutable
    };
  }

  private resolveProcmonExecutable(): string | null {
    const candidates = [
      process.env.PCAP_ANALYZER_PROCMON,
      path.join(process.resourcesPath, 'procmon', 'Procmon64.exe'),
      path.join(process.resourcesPath, 'procmon', 'Procmon.exe'),
      path.join(app.getAppPath(), 'vendor', 'procmon', 'Procmon64.exe'),
      path.join(app.getAppPath(), 'vendor', 'procmon', 'Procmon.exe'),
      ...DEV_PROCMon_CANDIDATES
    ].filter((value): value is string => Boolean(value));

    for (const candidate of candidates) {
      if (this.isExecutableResolvable(candidate)) {
        return candidate;
      }
    }

    return null;
  }

  private isExecutableResolvable(candidate: string): boolean {
    const hasPathHint = candidate.includes('/') || candidate.includes('\\') || candidate.includes(':');
    if (!hasPathHint) {
      return this.resolveCommandInPath(candidate) !== null;
    }
    return fs.existsSync(candidate);
  }

  private resolveCommandInPath(command: string): string | null {
    const pathValue = process.env.PATH || process.env.Path || '';
    const pathParts = pathValue.split(path.delimiter).filter(Boolean);
    const extensions =
      process.platform === 'win32'
        ? ['.exe', '.cmd', '.bat', '']
        : [''];

    for (const dirPath of pathParts) {
      for (const extension of extensions) {
        const candidate = path.join(dirPath, `${command}${extension}`);
        if (fs.existsSync(candidate)) {
          return candidate;
        }
      }
    }

    return null;
  }

  private validateRequest(request: CorrelationRequest): string | null {
    if (!request.analysisId) return 'Brak analysisId.';
    if (!request.pcapFilePath) return 'Brak sciezki pliku PCAP.';
    if (!fs.existsSync(request.pcapFilePath)) return `Plik PCAP nie istnieje: ${request.pcapFilePath}`;
    if (!request.procmonFilePaths?.length) return 'Nie wybrano plikow Procmon.';

    for (const pmlPath of request.procmonFilePaths) {
      if (!fs.existsSync(pmlPath)) {
        return `Plik Procmon nie istnieje: ${pmlPath}`;
      }
    }

    return null;
  }

  private normalizeStage(value: unknown): CorrelationProgress['stage'] {
    if (
      value === 'prepare' ||
      value === 'ingest_pcap' ||
      value === 'ingest_procmon' ||
      value === 'align' ||
      value === 'match' ||
      value === 'finalize'
    ) {
      return value;
    }

    return 'prepare';
  }

  private safeNumber(value: unknown): number {
    if (typeof value === 'number' && Number.isFinite(value)) return value;
    if (typeof value === 'string') {
      const parsed = Number(value);
      if (Number.isFinite(parsed)) return parsed;
    }
    return 0;
  }
}
