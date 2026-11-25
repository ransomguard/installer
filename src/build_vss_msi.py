"""Build the Windows Installer storage component from a verified embedded runtime."""
import argparse
import hashlib
import json
import msilib as m
from msilib import schema, sequence
from pathlib import Path
import tempfile
import uuid

SERVICE="Ransom0Vss"
SID="S-1-5-80-3755250574-3201999084-3738073789-2921536738-940384076"
PRODUCT="{543C5137-5B50-4A1D-B411-1650EC006923}"
VERSION="0.6.26"
PACKAGE_DIR="0.6.0-preview.25"


def guid(label):
    return "{"+str(uuid.uuid5(uuid.UUID(PRODUCT.strip("{}")),label)).upper()+"}"


def execute(db,statement):
    v=db.OpenView(statement)
    v.Execute(None)
    v.Close()


def build(runtime, manifest, backend, output, volume_guid):
    volume = "\\\\?\\Volume{" + str(uuid.UUID(volume_guid.strip("{}"))) + "}" + chr(92)
    published=json.loads(manifest.read_text(encoding="utf-8-sig"))["files"]
    runtime_files={Path(k).name:v for k,v in published.items() if k.startswith("python/")}
    if (not m.AMD64 or "python.exe" not in runtime_files or "python313.dll" not in runtime_files
            or "python313._pth" not in runtime_files or output.exists()):
        raise ValueError("Expected a new output and the x64 packaged runtime")
    for name,expected in runtime_files.items():
        if hashlib.sha256((runtime/name).read_bytes()).hexdigest()!=expected:
            raise ValueError("Runtime hash mismatch: "+name)
    db=m.init_database(str(output),schema,"Ransom0 VSS Provider",PRODUCT,VERSION,"Ransom0")
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
        ("Bundle","ProgramFiles64Folder","R0VSS~1|Ransom0 VSS Provider"),
        ("Python","Bundle","STORPY~1|storage-python"),("Backend","Bundle","STORBA~1|storage-backend"),
        ("Modules","Backend","RANSOM~1|ransomguard"))
    add("Feature",("Storage",None,"Ransom0 VSS Provider",None,1,1,None,0))
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
    root_acl="O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    component("ProviderDirectory","Bundle",None)
    add("CreateFolder",("Bundle","ProviderDirectory"))
    add("MsiLockPermissionsEx",("AclProvider","Bundle","CreateFolder",root_acl,None))
    reg=r"SOFTWARE\Ransom0\VssBroker"
    reg_acl=f"O:SYG:SYD:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;{SID})"
    component("Config","Bundle","Volume",256|4|16)
    add("Registry",("Volume",2,reg,"Volume",volume,"Config"))
    add("MsiLockPermissionsEx",("AclVolume","Volume","Registry",reg_acl,None))
    for n in ("Owned","Requests","Deleted"):
        add("Registry",(n,2,reg+chr(92)+n,"+",None,"Config"))
        add("MsiLockPermissionsEx",("Acl"+n,n,"Registry",reg_acl,None))
    add("ServiceInstall",("VssProvider",SERVICE,"Ransom0 VSS Provider",16,3,32769,None,None,
                         None,None,"-I -B -m ransomguard.vss_broker",exe_cmp,"Volume-scoped VSS operations"))
    add("MsiLockPermissionsEx",("AclService","VssProvider","ServiceInstall",
        f"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x10;;;{SID})",None))
    add("ServiceControl",("RemoveVss",SERVICE,160,None,1,exe_cmp))
    db.Commit()
    return entries


if __name__=="__main__":
    p=argparse.ArgumentParser()
    for option in ("runtime","manifest","backend","output"):
        p.add_argument("--"+option,type=Path,required=True)
    p.add_argument("--volume-guid", required=True, help="Approved protected volume GUID for this package")
    args=p.parse_args()
    rows=build(**vars(args))
    args.output.with_suffix(".files.json").write_text(json.dumps(rows,indent=2),encoding="utf-8")
