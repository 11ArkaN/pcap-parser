!include "LogicLib.nsh"

!macro customInstall
  DetailPrint "Konfiguracja zaleznosci korelacji (Python + sidecar)..."
  ExecWait '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\resources\sidecar\install_runtime.ps1" -InstallDir "$INSTDIR"' $0
  ${If} $0 != 0
    MessageBox MB_ICONEXCLAMATION|MB_OK "Automatyczna konfiguracja zaleznosci korelacji zakonczona kodem: $0.$\r$\nSzczegoly bledu: $INSTDIR\install_runtime.log"
  ${EndIf}
!macroend
