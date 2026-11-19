using System;
using System.IO;
using System.IO.Compression;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

class RansomGuardManager : Form {
    string package;
    TextBox log = new TextBox();
    CheckBox lab = new CheckBox();
    Button install = new Button(), start = new Button(), status = new Button(), remove = new Button();
    bool internalPreview;
    JavaScriptSerializer json = new JavaScriptSerializer { MaxJsonLength = 1024*1024 };
    public RansomGuardManager(string root, bool uninstallRequested) {
        Icon=System.Drawing.Icon.ExtractAssociatedIcon(Application.ExecutablePath);
        package=root;Text="Ransom0 설치 및 관리";Width=780;Height=680;
        var manifest=json.Deserialize<Dictionary<string,object>>(File.ReadAllText(Path.Combine(root,"payload-manifest.json")));
        internalPreview=!Object.Equals(manifest["channel"],"isolated-lab");
        StartPosition=FormStartPosition.CenterScreen;MinimumSize=new System.Drawing.Size(780,680);
        var title=new Label{Text="Ransom0 시제품 — 설치 및 실행",Left=20,Top=18,Width=720,Height=30,Font=new System.Drawing.Font("Malgun Gothic",14)};Controls.Add(title);
        Controls.Add(new Label{Text=Object.Equals(manifest["channel"],"internal-preview")?"비공개 내부 시험판입니다. Microsoft 드라이버 서명을 설치 시 검증합니다.":internalPreview?"VM·호스트 PC 공용 시험판입니다. 시험 서명 허용·Secure Boot OFF가 필요하며 자동 변경하지 않습니다.":"현재 패키지는 시험 서명된 VM용입니다. 일반 PC 기본 보안 설정으로는 설치할 수 없습니다.",Left=20,Top=55,Width=720,Height=34});
        Controls.Add(new Label{Text="JEV API 키와 보호·복구 폴더는 설치 후 Ransom0의 설정에서 등록합니다.\nAPI 키·폴더·첫 복구 기준이 준비되기 전에는 자동 대응이 활성화되지 않습니다.\n업데이트 시 기존 보호 폴더와 네트워크 정책은 유지됩니다.\n설치 시 기존 인터넷·방화벽 설정을 유지합니다. 위협 대응 시 격리로 원격 접속이 끊길 수 있습니다.",Left=20,Top=102,Width=720,Height=90});
        lab.Text=internalPreview?"승인된 시험 VM/PC입니다. 위협 자동 대응 시 PC 전체 네트워크 격리에 동의합니다.":"시험 VM입니다. 설치 시 네트워크를 유지하며 위협 대응 시 격리에 동의합니다.";lab.SetBounds(20,220,720,28);Controls.Add(lab);
        install.Text="설치 / 업데이트";install.SetBounds(20,365,160,32);start.Text="실행";start.SetBounds(195,365,110,32);status.Text="상태 확인";status.SetBounds(320,365,120,32);
        Controls.Add(install);Controls.Add(start);Controls.Add(status);
        remove.Text="제거";remove.SetBounds(455,365,110,32);Controls.Add(remove);
        log.Multiline=true;log.ReadOnly=true;log.ScrollBars=ScrollBars.Both;log.SetBounds(20,412,720,210);log.Anchor=AnchorStyles.Top|AnchorStyles.Bottom|AnchorStyles.Left|AnchorStyles.Right;Controls.Add(log);
        install.Click+=async(s,e)=>{
            if(!lab.Checked){MessageBox.Show("시험 환경 및 통신 제한 동의 항목을 확인하세요.");return;}
            var request=new Dictionary<string,object>{{"isolated_lab",!internalPreview},{"internal_test",internalPreview},{"acknowledge_pc_wide_containment",lab.Checked}};
            await Run("install",json.Serialize(request));
        };
        start.Click+=async(s,e)=>await Run("start",null);
        status.Click+=async(s,e)=>await Run("status",null);
        remove.Click+=async(s,e)=>{
            if(MessageBox.Show("Ransom0 보호 기능을 제거할까요?\n복구·검토 중인 사건이 있으면 제거를 거부합니다. 기록·스냅샷·네트워크 정책은 보존합니다.","Ransom0 제거",MessageBoxButtons.YesNo)==DialogResult.Yes)await Run("uninstall",null);
        };
        Shown+=async(s,e)=>await Run(uninstallRequested?"plan-uninstall":"status",null);
    }
    void Append(string text){if(IsDisposed)return;BeginInvoke((Action)(()=>log.AppendText(text+Environment.NewLine)));}
    async Task Run(string command,string input){
        install.Enabled=start.Enabled=status.Enabled=remove.Enabled=false;
        try{
            int code=await Task.Run(()=>{
                var i=new ProcessStartInfo(Path.Combine(package,"python","python.exe"),"\""+Path.Combine(package,"setup","setup_engine.py")+"\" "+command+" --payload \""+package+"\"");
                i.UseShellExecute=false;i.CreateNoWindow=true;i.RedirectStandardOutput=true;i.RedirectStandardError=true;i.RedirectStandardInput=true;i.StandardOutputEncoding=Encoding.UTF8;i.StandardErrorEncoding=Encoding.UTF8;i.EnvironmentVariables["PYTHONIOENCODING"]="utf-8";
                using(var p=new Process{StartInfo=i}){
                    p.OutputDataReceived+=(s,e)=>{if(e.Data!=null)Append(Describe(command,e.Data));};p.ErrorDataReceived+=(s,e)=>{if(e.Data!=null)Append(e.Data);};
                    p.Start();p.BeginOutputReadLine();p.BeginErrorReadLine();if(input!=null)p.StandardInput.Write(input);p.StandardInput.Close();p.WaitForExit();return p.ExitCode;
                }
            });Append(code==0?"작업 완료":"작업을 완료하지 못했습니다. 위 사유를 확인하세요.");
        }catch(Exception ex){Append(ex.Message);}finally{install.Enabled=start.Enabled=status.Enabled=remove.Enabled=true;}
    }
    string Describe(string command,string line){
        if(!line.StartsWith("{"))return line;
        try{
            var d=json.Deserialize<Dictionary<string,object>>(line);
            if(command=="status"){
                var r=(Dictionary<string,object>)d["recovery"];var c=(Dictionary<string,object>)d["counters"];
                return "수집 상태: "+(Object.Equals(d["collector_ready"],true)?"정상":"시작 대기 또는 점검 필요")+Environment.NewLine+
                    "대응 모드: "+ResponseMode(d)+Environment.NewLine+
                    "복구 준비: "+(r.ContainsKey("ready")&&Object.Equals(r["ready"],true)?"사용 가능한 복구 목록 있음":"준비되지 않음")+Environment.NewLine+
                    "보호 폴더: "+(r.ContainsKey("protected_root")?r["protected_root"]:"미설정")+Environment.NewLine+
                    "누적 유실: "+(c.ContainsKey("events_dropped")?c["events_dropped"]:"확인 전")+Environment.NewLine+
                    (r.ContainsKey("detail")?"확인 사항: "+r["detail"]:"");
            }
            if(d.ContainsKey("state"))return "설치 상태: "+d["state"]+(d.ContainsKey("reboot_required")&&Object.Equals(d["reboot_required"],true)?Environment.NewLine+"파일 제거를 완료하려면 Windows를 다시 시작하세요.":"");
            return "실행 결과를 저장했습니다.";
        }catch{return line;}
    }
    string ResponseMode(Dictionary<string,object> d){
        object raw;if(!d.TryGetValue("runtime",out raw))return "확인 전 — 보호 완료로 간주하지 마세요";
        var runtime=raw as Dictionary<string,object>;object mode;
        if(runtime==null||!runtime.TryGetValue("mode",out mode))return "확인 전 — 보호 완료로 간주하지 마세요";
        string value=Convert.ToString(mode);
        if(value=="observe-only")return "수집·관찰만 — 자동 종료/복구 비활성 (JEV·복구 준비 확인 필요)";
        if(value=="scoped-live-track-a-b")return "선택 폴더 Track A/B 자동 대응 설정됨 (JEV 실제 통신은 별도 확인)";
        return value;
    }
    [STAThread] static int Main(string[] args){
        bool extractOnly=args.Length>0&&args[0]=="--extract-only";
        if(!extractOnly){Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);}
        string root=Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        try{
            using(var packed=Assembly.GetExecutingAssembly().GetManifestResourceStream("payload.zip")){
                if(packed!=null){
                    root=Path.Combine(Path.GetTempPath(),"RansomGuardSetup",Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
                    using(var zip=new ZipArchive(packed,ZipArchiveMode.Read))foreach(var entry in zip.Entries){
                        string dest=Path.GetFullPath(Path.Combine(root,entry.FullName));
                        if(!dest.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)||entry.FullName.Contains(":"))throw new InvalidDataException("Invalid payload path");
                        if(entry.Name.Length==0){Directory.CreateDirectory(dest);continue;}
                        Directory.CreateDirectory(Path.GetDirectoryName(dest));using(var source=entry.Open())using(var output=File.Create(dest))source.CopyTo(output);
                    }
                }
            }
            if(args.Length>0&&args[0]=="--extract-only"){Console.WriteLine(root);return 0;}
            Application.Run(new RansomGuardManager(root,args.Length>0&&args[0]=="--uninstall"));return 0;
        }catch(Exception ex){if(extractOnly)Console.Error.WriteLine(ex.ToString());else MessageBox.Show(ex.Message,"Ransom0");return 1;}
    }
}
