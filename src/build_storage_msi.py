"""Build the Windows Installer storage component from a verified embedded runtime."""
import argparse
import hashlib
import json
import msilib as m
from msilib import schema, sequence
from pathlib import Path
import tempfile
import uuid

SERVICE="Ransom0Storage"
SID="S-1-5-80-3755250574-3201999084-3738073789-2921536738-940384076"
PRODUCT="{269280E0-5E70-4EA1-AA8A-6A0962777B26}"
VERSION="0.6.26"
PACKAGE_DIR="0.6.0-preview.25"


def guid(label):
    return "{"+str(uuid.uuid5(uuid.UUID(PRODUCT.strip("{}")),label)).upper()+"}"


def execute(db,statement):
    v=db.OpenView(statement)
    v.Execute(None)
    v.Close()


def build(runtime, manifest, backend, output):
    published=json.loads(manifest.read_text(encoding="utf-8-sig"))["files"]
    runtime_files={Path(k).name:v for k,v in published.items() if k.startswith("python/")}
    if (not m.AMD64 or "python.exe" not in runtime_files or "python313.dll" not in runtime_files
            or "python313._pth" not in runtime_files or output.exists()):
        raise ValueError("Expected a new output and the x64 packaged runtime")
    for name,expected in runtime_files.items():
        if hashlib.sha256((runtime/name).read_bytes()).hexdigest()!=expected:
            raise ValueError("Runtime hash mismatch: "+name)
    db=m.init_database(str(output),schema,"Ransom0 Storage",PRODUCT,VERSION,"Ransom0")
    info=db.GetSummaryInformation(20)
    info.SetProperty(m.PID_PAGECOUNT,500)
    info.Persist()
    def add(table,*rows):
        m.add_data(db,table,list(rows))
    m.add_tables(db,sequence)
    # AppSearch must populate R0_FOUND_CORE before either sequence tests it.
    for table in ("InstallExecuteSequence","InstallUISequence"):
        execute(db,"UPDATE "+table+" SET Sequence=450 WHERE Action='LaunchConditions'")
    execute(db,"DROP TABLE `LockPermissions`")
    execute(db,"CREATE TABLE `MsiLockPermissionsEx` (`MsiLockPermissionsEx` CHAR(72) NOT NULL, "
            "`LockObject` CHAR(72) NOT NULL, `Table` CHAR(32) NOT NULL, `SDDLText` CHAR(0) NOT NULL, "
            "`Condition` CHAR(255) PRIMARY KEY `MsiLockPermissionsEx`)")
    add("Property",("ALLUSERS","1"),("ARPNOMODIFY","1"),("ARPComments","Dedicated manual-start database service."))
    add("RegLocator",("InstalledCore",2,r"SYSTEM\CurrentControlSet\Services\Anti_Ransom_Driver","ImagePath",18))
    add("AppSearch",("R0_FOUND_CORE","InstalledCore"))
    add("LaunchCondition",("Installed OR (VersionNT64 AND Privileged AND R0_FOUND_CORE)",
                           "The installed x64 Ransom0 Core and administrator rights are required."))
    add("Directory",("TARGETDIR",None,"SourceDir"),("ProgramFiles64Folder","TARGETDIR","."),
        ("Vendor","ProgramFiles64Folder","RANSOM~1|RansomGuard"),("Bundle","Vendor","R0PKG~1|"+PACKAGE_DIR),
        ("Python","Bundle","STORPY~1|storage-python"),("Backend","Bundle","STORBA~1|storage-backend"),
        ("Modules","Backend","RANSOM~1|ransomguard"),("State","Bundle","SERVIC~1|service-state"))
    add("Feature",("Storage",None,"Ransom0 Storage",None,1,1,None,0))
    cab=m.CAB("storage.cab")
    def component(key,folder,keypath,flags=256):
        add("Component",(key,guid(key),folder,flags,None,keypath))
        add("FeatureComponents",("Storage",key))
    entries=[]
    def file(src,name,folder):
        key="F"+hashlib.sha256((folder+"/"+name).encode()).hexdigest()[:20]
        cmp="C"+key[1:]
        i,_=cab.append(str(src),name,key)
        ext=Path(name).suffix[1:4] or "DAT"
        short=f"F{i:07d}.{ext}"
        component(cmp,folder,key)
        add("File",(key,cmp,short+"|"+name,src.stat().st_size,None,None,512,i))
        entries.append((key,folder,name,hashlib.sha256(src.read_bytes()).hexdigest()))
        return cmp
    with tempfile.TemporaryDirectory() as tmp:
        pth=Path(tmp)/"python313._pth"
        pth.write_bytes(b"python313.zip\r\n.\r\n../storage-backend\r\n")
        for name in sorted(runtime_files):
            cmp=file(pth if name==pth.name else runtime/name,name,"Python")
            if name=="python.exe":
                exe_cmp=cmp
        modules=sorted(backend.glob("*.py"))
        if not {"storage_service","storage_acceptance","storage_acl","service_migration","cli"}<={p.stem for p in modules}:
            raise ValueError("Incomplete storage service source")
        for source in modules:
            file(source,source.name,"Modules")
        cab.commit(db)
    rx="0x1200a9"
    for key,name,admin,service in (("State",None,rx,rx),("Private","private",rx,"FA"),
            ("Incoming","incoming",rx,rx),("Requests","requests","0x1301bf","FA"),("Answers","answers",rx,"FA")):
        if name:
            add("Directory",(key,"State",name))
        component("D"+key,key,None,256|16)  # Keep data on package removal.
        add("CreateFolder",(key,"D"+key))
        acl=f"O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;{admin};;;BA)(A;OICI;{service};;;{SID})"
        add("MsiLockPermissionsEx",("Acl"+key,key,"CreateFolder",acl,None))
    add("ServiceInstall",("StorageService",SERVICE,"Ransom0 Storage",16,3,32769,None,None,
                        "NT SERVICE\\"+SERVICE,None,"-I -B -m ransomguard.storage_service",exe_cmp,
                        "Ransom0 dedicated storage owner"))
    add("ServiceControl",("RemoveStorage",SERVICE,160,None,1,exe_cmp))
    db.Commit()
    return entries


if __name__=="__main__":
    p=argparse.ArgumentParser()
    for option in ("runtime","manifest","backend","output"):
        p.add_argument("--"+option,type=Path,required=True)
    args=p.parse_args()
    rows=build(**vars(args))
    args.output.with_suffix(".files.json").write_text(json.dumps(rows,indent=2),encoding="utf-8")
