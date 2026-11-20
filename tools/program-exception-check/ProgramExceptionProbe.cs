using System;
using System.IO;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Threading;
class ProgramExceptionProbe {
 static int Main(string[] args) {
  if(args.Length!=1)return 2;
  string home=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"Ransom0TestLab");
  string run=Path.GetFullPath(args[0]);
  if(!run.StartsWith(Path.Combine(home,"ProgramChecks")+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))return 3;
  string file=Path.Combine(home,"Protected","document-00.txt");
  if(!File.Exists(Path.Combine(home,"ownership.json")) || !File.Exists(file))return 4;
  Thread.Sleep(3000);
  byte[] content=new byte[8192];using(var rng=RandomNumberGenerator.Create())rng.GetBytes(content);
  File.WriteAllBytes(file,content);
  try {
   var start=new ProcessStartInfo(Path.Combine(run,"vssadmin.exe"),"delete shadows");
   start.UseShellExecute=false;start.CreateNoWindow=true;
   using(var p=Process.Start(start)) {if(!p.WaitForExit(10000))return 5;}
  }catch(System.ComponentModel.Win32Exception) {}
  Thread.Sleep(120000);
  return 0;
 }
}
