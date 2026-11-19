"""Build the user-mode intake DLL with the installed Visual C++ x64 toolchain."""
from pathlib import Path
import subprocess
import tempfile

def build():
    base=Path(__file__).resolve().parent
    vcvars=Path(r'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat')
    if not vcvars.is_file():
        raise RuntimeError('Visual C++ 2022 x64 tools are required to build intake_io.c')
    source=base/'backend/integration/windows/intake_io.c'
    output=base/'backend/native/rg_intake.dll'
    output.parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='ransom0-intake-',dir=base) as directory:
        tmp=Path(directory)
        command=tmp/'build.cmd'
        command.write_text('@echo off\ncall "'+str(vcvars)+'" >nul\nif errorlevel 1 exit /b 1\n'
            +'cl /nologo /LD /O2 /MT /W4 /WX /Fo:"'+str(tmp/'intake.obj')+'" "'+str(source)
            +'" /link /OUT:"'+str(output)+'" /IMPLIB:"'+str(tmp/'intake.lib')+'"\n',encoding='utf8')
        subprocess.run(['cmd.exe','/d','/c',str(command)],cwd=tmp,check=True)
    return output

if __name__=='__main__': print(build())
