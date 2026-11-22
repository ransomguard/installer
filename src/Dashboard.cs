using System;
using System.IO;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Web.Script.Serialization;
using System.Windows.Forms;

// Interactive entry point only. The existing integration owns protection startup.
class Ransom0Dashboard {
    [DllImport("user32.dll")] static extern bool ShowWindowAsync(IntPtr window, int command);
    [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr window);
    [STAThread] static int Main() {
        using(var gate=new System.Threading.Mutex(false,"Local\\Ransom0DashboardLauncher")) {
            bool owned=false;
            try {
                try {owned=gate.WaitOne(0);}catch(System.Threading.AbandonedMutexException){owned=true;}
                return owned?Run():0;
            }finally{if(owned)gate.ReleaseMutex();}
        }
    }
    static int Run() {
        Application.EnableVisualStyles();
        try {
            string receiptPath=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"RansomGuard","installation-receipt.json");
            var json=new JavaScriptSerializer();
            var receipt=json.Deserialize<Dictionary<string,object>>(File.ReadAllText(receiptPath));
            string state=Convert.ToString(receipt["state"]);
            if(state=="uninstalled" || state=="fresh_install_failed")throw new InvalidOperationException("Ransom0_install에서 먼저 설치해 주세요.");
            var paths=(Dictionary<string,object>)receipt["paths"];
            string runtime=Convert.ToString(receipt["runtime"]);
            string python=Convert.ToString(paths["python"]);
            string script=Path.Combine(runtime,"Start-RansomGuard.py");
            string ui=Path.GetFullPath(Convert.ToString(paths["ui"]));
            if(!File.Exists(python)||!File.Exists(script)||!File.Exists(ui))throw new FileNotFoundException("설치 파일을 찾을 수 없습니다. Ransom0_install에서 설치 상태를 확인해 주세요.");
            var info=new ProcessStartInfo(python,"\""+script+"\"");
            info.WorkingDirectory=runtime;info.UseShellExecute=false;info.CreateNoWindow=true;
            info.RedirectStandardOutput=true;info.RedirectStandardError=true;
            using(var process=Process.Start(info)) {
                var output=process.StandardOutput.ReadToEndAsync();
                var error=process.StandardError.ReadToEndAsync();
                process.WaitForExit();System.Threading.Tasks.Task.WaitAll(output,error);
                if(process.ExitCode!=0)throw new InvalidOperationException("대시보드 실행에 실패했습니다. Ransom0_install의 상태 확인을 이용해 주세요.\n"+error.Result);
            }
            int pid;
            if(Int32.TryParse(File.ReadAllText(Path.Combine(runtime,"ui.pid")).Trim(),out pid)) {
                using(var process=Process.GetProcessById(pid)) {
                    if(!String.Equals(Path.GetFullPath(process.MainModule.FileName),ui,StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("대시보드 프로세스 식별이 일치하지 않습니다.");
                    for(int i=0;i<40;i++) {
                        process.Refresh();var window=process.MainWindowHandle;
                        if(window!=IntPtr.Zero){ShowWindowAsync(window,9);SetForegroundWindow(window);break;}
                        System.Threading.Thread.Sleep(250);
                    }
                }
            }
            return 0;
        }catch(Exception error){MessageBox.Show(error.Message,"Ransom0",MessageBoxButtons.OK,MessageBoxIcon.Error);return 1;}
    }
}
