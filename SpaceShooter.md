> A nation-state APT group known as DarkVector has been conducting cyberattacks against our country's critical infrastructure. During a counter-operation, our red team captured a suspicious Android application deployed by the group as part of their staging infrastructure. The application is disguised as a simple mobile game — Space Shooter — but intelligence suggests it contains an embedded operational key used for C2 authentication.

The zip file contains the APK `spaceshooter.apk`

## Static analysis

After opening the app in `jadx-gui` we quickly see in the `AndroidManifest.xml` that it's a Unity app:

```xml
<activity
	android:theme="@style/UnityThemeSelector"
	android:name="com.unity3d.player.UnityPlayerActivity"
	android:enabled="true"
	android:exported="true"
```

In a Unity app the whole logic is inside the `libil2cpp.so`. In order to reverse it we use Il2CppDumper https://github.com/Perfare/Il2CppDumper
For that we need to extract the `/lib/arm64-v8a/libil2cpp.so` and `/assets/bin/Data/Managed/Metadata/global-metadata.dat`. 

**Note:** This tool is for Windows, not sure if it runs with wine, I have only tried it in a Windows VM.

We run into a problem though at first:
```powershell
PS C:\CTF\mobile_spaceshooter > .\Il2CppDumper-net6-win-v6.7.46\Il2CppDumper.exe .\libil2cpp.so .\global-metadata.dat .\out
Initializing metadata...
System.NotSupportedException: ERROR: Metadata file supplied is not a supported version[39].
   at Il2CppDumper.Metadata..ctor(Stream stream) in C:\projects\il2cppdumper\Il2CppDumper\Il2Cpp\Metadata.cs:line 57
   at Il2CppDumper.Program.Init(String il2cppPath, String metadataPath, Metadata& metadata, Il2Cpp& il2Cpp) in C:\projects\il2cppdumper\Il2CppDumper\Program.cs:line 123
   at Il2CppDumper.Program.Main(String[] args) in C:\projects\il2cppdumper\Il2CppDumper\Program.cs:line 97
Press any key to exit...
```

The latest release of Il2CppDumper (6.7.46) does not support metadata version v39 yet, but there is a pull request adding it: https://github.com/Perfare/Il2CppDumper/pull/903

```powershell
PS C:\CTF\mobile_spaceshooter > .\Il2CppDumper\Il2CppDumper\bin\Release\net8.0\Il2CppDumper.exe .\libil2cpp.so .\global-metadata.dat out
Initializing metadata...
Metadata Version: 39
Initializing il2cpp file...
Applying relocations...
WARNING: find JNI_OnLoad
ERROR: This file may be protected.
Il2Cpp Version: 39
Searching...
CodeRegistration : 1e9d058
MetadataRegistration : 1f64a88
Dumping...
Done!
Generate struct...
Done!
Generate dummy dll...
Done!
```
The script generated a dummy dll (`./out/DummyDll/Assembly-CSharp.dll`, which we can look at in dnSpy. We find some typical game classes for the Space Shooter game and then a class `NightfallCore` with some interesting methods...
![DLL classes](./attachments/4f934e87ed6d459eec81ee9e6b768fd7_MD5.png

The dummy DLL does not contain the code of the method, just the method heads and pointers. We now could go ahead with static analysis with Ghidra, e.g. following https://gist.github.com/BadMagic100/47096cbcf64ec0509cf75d48cfbdaea5, however, we can also check out the methods of `NightfallCore` with Frida.

## Dynamic Analysis of NightfallCore class

Luckily there is a il2cpp bridge for frida, so we can easily interact with these classes: https://github.com/vfsfitvnm/frida-il2cpp-bridge. The wiki contains detailed instructions for the setup as well as examples: https://github.com/vfsfitvnm/frida-il2cpp-bridge/wiki/Installation

In our case we start with the `package.json` file:

```json
{
  "name": "frida-il2cpp-script",
  "version": "1.0.0",
  "main": "index.ts",
  "scripts": {
    "spawn": "frida -U -f com.nightfall.binarytrace -l dist/agent.js",
    "watch": "frida-compile src/index.ts -o dist/agent.js -w",
    "build": "frida-compile src/index.ts -o dist/agent.js -c"
  },
  "keywords": [],
  "author": "",
  "license": "ISC",
  "description": "",
  "devDependencies": {
    "@types/frida-gum": "^19.0.1",
    "@types/node": "^24.10.1",
    "frida-compile": "^19.0.4",
    "frida-il2cpp-bridge": "^0.12.1",
    "typescript": "^5.9.3"
  }
}
```

And then implement our frida hook in `src/index.ts` and we start by just invoking the `GetClearanceToken` method and log the response.
```js
import 'frida-il2cpp-bridge'

Il2Cpp.perform(function() {
    console.log('il2cpp.so loaded')

    // Get the image of the Assembly-CSharp.dll
    const AssemblyCSharp = Il2Cpp.domain.assembly("Assembly-CSharp").image

    // Get the image of a class
    const NightfallCore = AssemblyCSharp.class("NightfallCore")
	
	// invoke GetClearanceToken
    const token = NightfallCore.method<Il2Cpp.Array>("GetClearanceToken").invoke()
    console.log(token)
})
```

```shell
┌──(.mobile-venv)─(kali㉿kali)-[~/Documents/frida-spaceshooter]
└─$ npm install
npm warn deprecated prebuild-install@7.1.3: No longer maintained. Please contact the author of the relevant native addon; alternatives are available.

added 49 packages, and audited 50 packages in 6s

11 packages are looking for funding
  run `npm fund` for details

found 0 vulnerabilities

┌──(.mobile-venv)─(kali㉿kali)-[~/Documents/frida-spaceshooter]
└─$ npm run build

> frida-il2cpp-script@1.0.0 build
> frida-compile src/index.ts -o dist/agent.js -c


┌──(.mobile-venv)─(kali㉿kali)-[~/Documents/frida-spaceshooter]
└─$ npm run spawn

> frida-il2cpp-script@1.0.0 spawn
> frida -U -f com.nightfall.binarytrace -l dist/agent.js

     ____
    / _  |   Frida 17.9.1 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Mi A2 Lite (id=192.168.1.117:5555)
Spawned `com.nightfall.binarytrace`. Resuming main thread!              
[Mi A2 Lite::com.nightfall.binarytrace ]-> il2cpp.so loaded
"HTB{darkvector_runtime_invoke_pwned}"

```
