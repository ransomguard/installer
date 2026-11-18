using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Win32;

// Read-only. No shell, network, credential reads, driver load or policy changes.
class RansomGuardReadiness {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct OsVersion {
        public uint size,major,minor,build,platform;
        [MarshalAs(UnmanagedType.ByValTStr,SizeConst=128)] public string servicePack;
    }
    [StructLayout(LayoutKind.Sequential)] struct CiInfo { public uint length, options; }
    [StructLayout(LayoutKind.Sequential)] struct MemoryInfo {
        public uint length,load; public ulong physical,availablePhysical,pageFile,availablePageFile,virtualTotal,availableVirtual,extended;
    }
    [DllImport("ntdll.dll")] static extern int RtlGetVersion(ref OsVersion version);
    [DllImport("ntdll.dll")] static extern int NtQuerySystemInformation(int kind,ref CiInfo value,uint size,out uint returned);
    [DllImport("kernel32.dll")] static extern void GetNativeSystemInfo(IntPtr info);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFirmwareType(out uint kind);
    [DllImport("kernel32.dll")] static extern bool GlobalMemoryStatusEx(ref MemoryInfo info);
    static object Read(RegistryKey hive,string path,string name) { try { using(var k=hive.OpenSubKey(path))return k==null?null:k.GetValue(name); }catch{return null;} }
    static Dictionary<string,object> Inspect() {
        var d=new Dictionary<string,object>();d["schema"]=1;d["read_only"]=true;d["network_request"]=false;
        var v=new OsVersion{size=(uint)Marshal.SizeOf(typeof(OsVersion))};
        d["build"]=RtlGetVersion(ref v)==0?(object)v.build:null;
        var ptr=Marshal.AllocHGlobal(64);
        try {GetNativeSystemInfo(ptr);int arch=Marshal.ReadInt16(ptr);d["architecture"]=arch==9?"x64":arch==12?"ARM64":arch==0?"x86":"unknown";}finally{Marshal.FreeHGlobal(ptr);}
        d["elevated"]=new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        var ci=new CiInfo{length=8};uint ret;
        bool ciKnown=NtQuerySystemInformation(103,ref ci,8,out ret)==0;
        d["code_integrity_known"]=ciKnown;d["test_signing"]=ciKnown?(object)((ci.options&2)!=0):null;
        d["hvci"]=ciKnown?(object)((ci.options&0x400)!=0):null;
        uint firmware;bool fwKnown=GetFirmwareType(out firmware);
        d["firmware"]=fwKnown?(firmware==1?"BIOS":firmware==2?"UEFI":"unknown"):"unknown";
        using(var lm=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64)) {
            object secure=Read(lm,@"SYSTEM\CurrentControlSet\Control\SecureBoot\State","UEFISecureBootEnabled");
            d["secure_boot"]=fwKnown&&firmware==1?(object)false:secure==null?null:(object)(Convert.ToInt32(secure)==1);
            d["vss_disabled"]=Object.Equals(Read(lm,@"SYSTEM\CurrentControlSet\Services\VSS","Start"),4);
            var collisions=new List<string>();bool complete=true;
            try {using(var services=lm.OpenSubKey(@"SYSTEM\CurrentControlSet\Services")) {
                foreach(string service in services.GetSubKeyNames()) {
                    if(service=="Anti_Ransom_FsFilter")continue;
                    foreach(string suffix in new[]{@"\Instances",@"\Parameters\Instances"}) {
                        using(var instances=services.OpenSubKey(service+suffix)) {
                            if(instances==null)continue;
                            foreach(string instance in instances.GetSubKeyNames()) {
                                object alt=Read(instances,instance,"Altitude");decimal value;
                                if(alt!=null&&Decimal.TryParse(Convert.ToString(alt),System.Globalization.NumberStyles.Number,System.Globalization.CultureInfo.InvariantCulture,out value)&&value==385090)collisions.Add(service);
                            }
                        }
                    }
                }
            }}catch{complete=false;}
            d["altitude_scan_complete"]=complete;d["altitude_conflicts"]=collisions.ToArray();
        }
        var mem=new MemoryInfo{length=(uint)Marshal.SizeOf(typeof(MemoryInfo))};
        d["ram_bytes"]=GlobalMemoryStatusEx(ref mem)?(object)mem.physical:null;
        try {var disk=new DriveInfo(Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows)));d["system_disk_free_bytes"]=disk.AvailableFreeSpace;d["system_filesystem"]=disk.DriveFormat;}catch{d["system_disk_free_bytes"]=null;d["system_filesystem"]="unknown";}
        return d;
    }
    [STAThread] static int Main(string[] args) {
        try {
            var data=Inspect();var json=new JavaScriptSerializer();string output=json.Serialize(data);
            if(args.Length==1&&args[0]=="--json"){Console.OutputEncoding=System.Text.Encoding.UTF8;Console.WriteLine(output);return 0;}
            Application.EnableVisualStyles();
            string summary="RansomGuard 설치 전 검사 (설정 변경 없음)\r\n\r\n"+
                "Windows 빌드: "+data["build"]+" / "+data["architecture"]+"\r\n"+
                "시험 서명 허용: "+data["test_signing"]+"\r\n보안 부팅: "+data["secure_boot"]+"\r\n메모리 무결성(HVCI): "+data["hvci"]+"\r\n"+
                "\r\n현재 VM 시험판은 시험 드라이버를 허용하도록 별도로 준비한 격리 VM이 필요합니다.\r\n일반 보안 설정의 PC에 바로 설치할 수 있는 Microsoft 서명판은 아직 없습니다.\r\n이 검사는 설치 성공이나 보호 기능의 정상 작동을 보증하지 않습니다.\r\n\r\n"+output;
            var form=new Form{Text="RansomGuard 설치 가능 여부",Width=760,Height=540,StartPosition=FormStartPosition.CenterScreen};
            form.Controls.Add(new TextBox{Multiline=true,ReadOnly=true,Dock=DockStyle.Fill,ScrollBars=ScrollBars.Both,Text=summary});
            var save=new Button{Text="검사 결과 저장",Dock=DockStyle.Bottom,Height=36};form.Controls.Add(save);
            save.Click+=(s,e)=>{using(var dialog=new SaveFileDialog{FileName="RansomGuard-readiness.json",Filter="JSON|*.json"}){if(dialog.ShowDialog()==DialogResult.OK)File.WriteAllText(dialog.FileName,output,new System.Text.UTF8Encoding(false));}};
            Application.Run(form);return 0;
        }catch(Exception e){Console.WriteLine(new JavaScriptSerializer().Serialize(new{error="readiness_failed",category=e.GetType().Name}));return 2;}
    }
}
