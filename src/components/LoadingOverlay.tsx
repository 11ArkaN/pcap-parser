import React from 'react';
import type { LoadingProgress } from '../types';

interface LoadingOverlayProps {
  progress: LoadingProgress;
}

function LoadingOverlay({ progress }: LoadingOverlayProps) {
  const percentage = progress.total > 0 ? Math.round((progress.current / progress.total) * 100) : 0;

  return (
    <div className="loading-overlay">
      <div className="loading-spinner" />
      <p className="loading-text">{progress.text}</p>

      {progress.total > 0 && (
        <div className="progress-container">
          <div className="progress-bar">
            <div className="progress-fill" style={{ width: `${percentage}%` }} />
          </div>
          <div className="progress-stats">
            <span>
              {progress.current} / {progress.total}
            </span>
            <span>{percentage}%</span>
          </div>
        </div>
      )}
    </div>
  );
}

export default LoadingOverlay;
