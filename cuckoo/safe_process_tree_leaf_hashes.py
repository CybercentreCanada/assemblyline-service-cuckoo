SAFE_PROCESS_TREE_LEAF_HASHES = {
    "d3b14a95c2160abc76f356b5e9b79c71c91035e49f1c5962ce7a100e61decd78": {
        "image": "?sys32\\lsass.exe",
        "command_line": "C:\\WINDOWS\\system32\\lsass.exe",
        "children": []
    },
    "f405c23c52c0dd0cd7ac31f92df0e76f9c6702b155ca5be6afbc076bb81d82a6": {
        "image": "?pf86\\common files\\microsoft shared\\officesoftwareprotectionplatform\\osppsvc.exe",
        "command_line": "\"C:\\Program Files\\Common Files\\Microsoft Shared\\OfficeSoftwareProtectionPlatform\\OSPPSVC.EXE\"",
        "children": []
    },
    "a1d7889895b3a83edb3306c85df424da544369567d860215a75f5cbffe635375": {
        "image": '?sys32\\lsass.exe',
        "command_line": None,
        "children": [
            {
                "image": '?sys32\\services.exe',
                "command_line": None,
                "children": [
                    {
                        "image": "?pf86\\common files\\microsoft shared\\officesoftwareprotectionplatform\\osppsvc.exe",
                        "command_line": "\"C:\\Program Files\\Common Files\\Microsoft Shared\\OfficeSoftwareProtectionPlatform\\OSPPSVC.EXE\"",
                        "children": []
                    }
                ]
            }
        ]
    },
    "7e2c38006c7720d214b726be34bf3bbfca1c8f02c3b36f7c8b7c7198f119c8a2": {
        "image": "?sys32\\sppsvc.exe",
        "command_line": "C:\\Windows\\system32\\sppsvc.exe",
        "children": []
    },
    "2f6044eb59e4d5104cfd7025ffd14fe2bea9405c566f7f4ecc9548f694fad00a": {
        "image": "?sys32\\svchost.exe",
        "command_line": "C:\\WINDOWS\\System32\\svchost.exe -k WerSvcGroup",
        "children": [
            {
                "image": "?sys32\\werfault.exe",
                "command_line": "C:\\WINDOWS\\system32\\WerFault.exe -pss -s 476 -p 3168 -ip 3168",
                "children": []
            }
        ]
    },
    "b04893383338161ca8bec608cb9b877acf5c6708cbc4244ec5d0f49f5ab4b9f1": {
        "image": "?sys32\\slui.exe",
        "command_line": "C:\\WINDOWS\\System32\\slui.exe -Embedding",
        "children": []
    },
    "01bf5d0579b4db52ee0322f9f84b7db238c037a2d32b4969298830612ffbdcf8": {
        "image": "?sys32\\backgroundtaskhost.exe",
        "command_line": "\"C:\\WINDOWS\\system32\\backgroundTaskHost.exe\" -ServerName:App.AppXmtcan0h2tfbfy7k9kn8hbxb6dmzz1zh0.mca",
        "children": []
    },
    "a53afad8f3925d95edace69eb6e68184b3d52bdaae0bacdd2f7df5ede70446a8": {
        "image": "?pf86\\windowsapps\\microsoft.windowscommunicationsapps_16005.13426.20920.0_x64__8wekyb3d8bbwe\\hxtsr.exe",
        "command_line": "\"C:\\Program Files\\WindowsApps\\microsoft.windowscommunicationsapps_16005.13426.20920.0_x64__8wekyb3d8bbwe\\HxTsr.exe\" -ServerName:Hx.IPC.Server",
        "children": []
    },
    "1fc2ec278dbd4f03d4a6ea748d35f75b554e43b8211fc5bcebb2ff295e03182b": {
        "image": "?sys32\\runtimebroker.exe",
        "command_line": "C:\\Windows\\System32\\RuntimeBroker.exe -Embedding",
        "children": []
    },
    "51b9684487d1a103549ec6f5773e058932073037dc30fdb6580c9c388503cf74": {
        "image": "?sys32\\conhost.exe",
        "command_line": "\\??\\C:\\WINDOWS\\system32\\conhost.exe 0xffffffff -ForceV1",
        "children": []
    },
    "ddb872aa77c4c7ba1ec280f77e1a2f19cbd4d461fe21da009f89ade882fe26be": {
        "image": "?win\\explorer.exe",
        "command_line": "C:\\WINDOWS\\Explorer.EXE",
        "children": []
    },
    "f3d6ed01b460589fbebaf89c2fcad5503bf4d86993fb20d410eace46a595108f": {
        "image": "?sys32\\svchost.exe",
        "command_line": "C:\\WINDOWS\\System32\\svchost.exe -k WerSvcGroup",
        "children": []
    },
    "d1c20b94425d2d866bdd30adc1af7d7ce5b08c30c7418f618d8164ac06ae76ee": {
        "image": "?sys32\\dllhost.exe",
        "command_line": "C:\\Windows\\system32\\DllHost.exe /Processid:{F9717507-6651-4EDB-BFF7-AE615179BCCF}",
        "children": []
    },
    "9c58c41fb2916bea2d6059e912a55c5505ce0b3b7b78cdf6ee3321387ce0f0ae": {
        "image": "?sys32\\wbem\\wmiprvse.exe",
        "command_line": "C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding",
        "children": []
    },
    # FP since we only look at the image here
    # "3e3793b897525f211e7425c45df068b2594bb4ad8dcf731f5771fd30233d721b": {
    #     "image": "?sys32\\rundll32.exe",
    #     "command_line": "C:\\WINDOWS\\system32\\rundll32.exe C:\\WINDOWS\\system32\\PcaSvc.dll,PcaPatchSdbTask",
    #     "children": []
    # },
    "ab2bf0e9666652ed8254b079209e27568e0e55a4418cfe94a48181f34625ff15": {
        "image": "?sys32\\sc.exe",
        "command_line": "C:\\WINDOWS\\system32\\sc.exe start wuauserv",
        "children": [
            {
                "image": "?sys32\\conhost.exe",
                "command_line": "\\??\\C:\\WINDOWS\\system32\\conhost.exe 0xffffffff -ForceV1",
                "children": []
            }
        ]
    },
    "2dd065baf9009515b0d68a64a7cf324ff325893fb8ca630febed2950a3be7432": {
        "image": "?sys32\\wermgr.exe",
        "command_line": "\"C:\\WINDOWS\\system32\\wermgr.exe\" \"-outproc\" \"0\" \"2720\" \"1936\" \"1868\" \"1940\" \"0\" \"0\" \"0\" \"0\" \"0\" \"0\" \"0\" \"0\"",
        "children": []
    },
    "50c958b80515a739a7a9397890d310a91d1e3593ab1aae7757331d71768ccc4a": {
        "image": "?sys32\\sc.exe",
        "command_line": "C:\\Windows\\system32\\sc.exe start w32time task_started",
        "children": []
    },
    "faac8a70045bd7596a1f1e368e346130e357b6f5e8b043287653dfe1fabb12b9": {
        "image": "?sys32\\sdclt.exe",
        "command_line": "C:\\Windows\\System32\\sdclt.exe /CONFIGNOTIFICATION",
        "children": []
    },
    "d922fb8a674c43236b96805a7ba2d4090f0cb7e6ae12d0186339c9ad489c6386": {
        "image": "?sys32\\taskhost.exe",
        "command_line": "taskhost.exe $(Arg0)",
        "children": []
    },
    "e7a3087aba99f3aa0dd4aa5a44d0be58256b4ef41be49da617026838f5204f5c": {
        "image": "?win\\systemapps\\microsoftwindows.client.cbs_cw5n1h2txyewy\\inputapp\\textinputhost.exe",
        "command_line": "\"C:\\Windows\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\InputApp\\TextInputHost.exe\" -ServerName:InputApp.AppX9jnwykgrccxc8by3hsrsh07r423xzvav.mca",
        "children": []
    },
    "04184d24f08dadab15c91374f7aedba484d8214d0d3c2e8b240e3b7b6f25d959": {
        "image": '?sys32\\svchost.exe',
        "command_line": None,
        "children": [
            {
                "image": "?win\\systemapps\\microsoftwindows.client.cbs_cw5n1h2txyewy\\inputapp\\textinputhost.exe",
                "command_line": "\"C:\\Windows\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\InputApp\\TextInputHost.exe\" -ServerName:InputApp.AppX9jnwykgrccxc8by3hsrsh07r423xzvav.mca",
                "children": []
            }
        ]
    },
    "24954e76154b030985354403bdb85d0a334c0007c842f5381ed8a0544f11466b": {
        "image": "?sys32\\wbem\\wmiadap.exe",
        "command_line": "wmiadap.exe /F /T /R",
        "children": []
    },
    "a7756c96db89aaf251d32633e40b57c104807060c3f7c650c0b94ea90cb0458b": {
        "image": "?win\\explorer.exe",
        "command_line": "C:\\WINDOWS\\Explorer.EXE",
        "children": [
            {
                "image": "?sys32\\werfault.exe",
                "command_line": "C:\\WINDOWS\\system32\\WerFault.exe -u -p 6080 -s 6792",
                "children": []
            }
        ]
    },
    "aa5dd26518bf22e0d6ca76b67a2295934aa52858ec19b47affadf99cbd328a2e": {
        "image": "?win\\systemapps\\microsoft.windows.startmenuexperiencehost_cw5n1h2txyewy\\startmenuexperiencehost.exe",
        "command_line": "\"C:\\Windows\\SystemApps\\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\\StartMenuExperienceHost.exe\" -ServerName:App.AppXywbrabmsek0gm3tkwpr5kwzbs55tkqay.mca",
        "children": []
    },
    "44dcdb8d08f7fdcfe0843d73a652ddbe1e1729fdfdcb66e8f009d3f82a3103ea": {
        "image": "?win\\systemapps\\microsoft.windows.search_cw5n1h2txyewy\\searchapp.exe",
        "command_line": "\"C:\\Windows\\SystemApps\\Microsoft.Windows.Search_cw5n1h2txyewy\\SearchApp.exe\" -ServerName:CortanaUI.AppX8z9r6jm96hw4bsbneegw0kyxx296wr9t.mca",
        "children": []
    },
    "6a27c89bdbe4f9855307c59f8c8a480e9a76681cf533d18690754baa250228db": {
        "image": "?sys32\\mobsync.exe",
        "command_line": "C:\\WINDOWS\\System32\\mobsync.exe -Embedding",
        "children": []
    },
    "b12bbea6f1a504c7288762f649b849457edbee81b4967863dad67f3158b250fb": {
        "image": "?sys32\\musnotifyicon.exe",
        "command_line": "%%systemroot%%\\system32\\MusNotifyIcon.exe NotifyTrayIcon 0",
        "children": []
    },
    "bcb1213942dd880cc729f5b6cad820e1cc0c0c92cdd4ab3e3919edd6e40fbb64": {
        "image": "?pf86\\windowsapps\\microsoft.xboxgamingoverlay_5.621.4222.0_x64__8wekyb3d8bbwe\\gamebar.exe",
        "command_line": "\"C:\\Program Files\\WindowsApps\\Microsoft.XboxGamingOverlay_5.621.4222.0_x64__8wekyb3d8bbwe\\GameBar.exe\" -ServerName:App.AppXbdkk0yrkwpcgeaem8zk81k8py1eaahny.mca",
        "children": []
    },
    "fd4fad363ee4c67ab9826cff5ab63d8a68bde96c63b60d70bc7654d26695e469": {
        "image": "?pf86\\windowsapps\\microsoft.xboxgamingoverlay_5.621.4222.0_x64__8wekyb3d8bbwe\\gamebarftserver.exe",
        "command_line": "\"C:\\Program Files\\WindowsApps\\Microsoft.XboxGamingOverlay_5.621.4222.0_x64__8wekyb3d8bbwe\\GameBarFTServer.exe\" -Embedding",
        "children": []
    },
    "f3de6d0a84196f1af3fe985f772c7a4dd23a7979286e78c9928d3f3fcb090a82": {
        "image": "?sys32\\backgroundtransferhost.exe",
        "command_line": "\"BackgroundTransferHost.exe\" -ServerName:BackgroundTransferHost.1",
        "children": []
    },
    "73eb56621fbdbdfaeb669105ba4eb327854790d55994a23a2f852fed8bf9b9af": {
        "image": "?sys32\\backgroundtaskhost.exe",
        "command_line": "\"C:\\WINDOWS\\system32\\backgroundTaskHost.exe\" -ServerName:App.AppXmtcan0h2tfbfy7k9kn8hbxb6dmzz1zh0.mca",
        "children": [
            {
                "image": "?sys32\\conhost.exe",
                "command_line": "\\??\\C:\\WINDOWS\\system32\\conhost.exe 0xffffffff -ForceV1",
                "children": []
            }
        ]
    },
    "0e3b8b7c5bbffdf8923f5acd914194d7f5db897b73a0f0541dc13750e4af718a": {
        "image": "?sys32\\werfault.exe",
        "command_line": "C:\\WINDOWS\\system32\\WerFault.exe -pss -s 484 -p 6448 -ip 6448",
        "children": []
    },
    "25a026bdd54385f3aaefb8e1723f5be97b7c36e255b2c48f7f7f8a66d9df7eb8": {
        "image": "?sys32\\waasmedicagent.exe",
        "command_line": "C:\\WINDOWS\\System32\\WaaSMedicAgent.exe 843c17b493dbd4989beed27582c82422 sXMpv2EzyEqV2L6NYnvYjw.0.1.0.0.0",
        "children": []
    },
    "54e726d55dcb6c6c4914a0ae899d89c454442624fa64c824bee9110b4abc7721": {
        "image": "?sys32\\sc.exe",
        "command_line": "C:\\WINDOWS\\system32\\sc.exe start pushtoinstall registration",
        "children": [
            {
                "image": "?sys32\\conhost.exe",
                "command_line": "\\??\\C:\\WINDOWS\\system32\\conhost.exe 0xffffffff -ForceV1",
                "children": [
                    {
                        "image": "?sys32\\wermgr.exe",
                        "command_line": "\"C:\\WINDOWS\\system32\\wermgr.exe\" \"-outproc\" \"0\" \"1072\" \"1928\" \"1876\" \"1932\" \"0\" \"0\" \"0\" \"0\" \"0\" \"0\" \"0\" \"0\"",
                        "children": []
                    }
                ]
            }
        ]
    },
    "bbc5e661e106c6dcd8dc6dd186454c2fcba3c710fb4d8e71a60c93eaf077f073": {
        "image": "system",
        "command_line": None,
        "children": []
    },
    "acbf70b95a96ba178eb89269e7f1db5f622fa4b6b009cd29284d7be14024625b": {
        "image": "?sys32\\searchindexer.exe",
        "command_line": None,
        "children": []
    },
    "49a2ab6c73a10ee6bd97a0ba200c6f6dc0dc2977059b8029579e780748f19c72": {
        "image": "?c\\python27\\pythonw.exe",
        "command_line": None,
        "children": []
    },
    "49d9994a34643bea4cc71a26501d1e58ccabd051a1cf9704184b6374e1ef3764": {
        "image": "?sys32\\searchprotocolhost.exe",
        "command_line": None,
        "children": []
    },
    "a54f2146bd3272b89f7b9c7047f2b436a9514f89feeed754bcc6d19d32dc2db3": {
        "image": "?sys32\\searchfilterhost.exe",
        "command_line": None,
        "children": []
    },
    "1d038671bb56576c62a176c7902e6867a978732d1ecafe792c8ac6ac3dde79ba": {
        "image": "?sys32\\svchost.exe",
        "command_line": None,
        "children": [
            {
                "image": "?win\\explorer.exe",
                "command_line": None,
                "children": []
            }
        ]
    },
    "5f4653a82121522720fbb9bdab186d70bf7f21e1ca475cb87b12f448ea71e1ca": {
        "image": "?sys32\\svchost.exe",
        "command_line": None,
        "children": [
            {
                "image": "?sys32\\conhost.exe",
                "command_line": "\\??\\C:\\Windows\\system32\\conhost.exe \"-28232134049486641315307486691639655269-80106784-108753052346563986-549529209\"",
                "children": []
            }
        ]
    },
    "78f84277f3383d654d64679ea93be5614d09b588006f0e9ca7395bb797a6f942": {
        "image": "?sys32\\svchost.exe",
        "command_line": None,
        "children": [
            {
                "image": '?c\\python27\\pythonw.exe',
                "command_line": None,
                "children": []
            }
        ]
    },
    "da60beb532bc62cd2208910c086bcbabc4488d45e2dcc4e8414b3969e7902fc7": {
        "image": "?sys32\\svchost.exe",
        "command_line": None,
        "children": [
            {
                "image": "?sys32\\svchost.exe",
                "command_line": None,
                "children": []
            }
        ]
    },
    "6dea6b390c3611c05f7ce0a8d56b136431168161237ae254f4f0a3eeedb52fa9": {
        "image": "?sys32\\userinit.exe",
        "command_line": None,
        "children": []
    },
    "fe1b33fe682a3ce734f5e66aface2e59bad7a91741a6166b793e1658a44cab7b": {
        "image": "?win\\microsoft.net\\framework64\\v4.0.30319\\mscorsvw.exe",
        "command_line": None,
        "children": []
    },
    "eea8165b1ac8e04a4257e249753f1b8085e712521e3fc44718a49bb94851ff1b": {
        "image": "?win\\microsoft.net\\framework\\v4.0.30319\\mscorsvw.exe",
        "command_line": None,
        "children": []
    },
    "5a5f1f8bf9b80413fff222a0a88c3c52c018f9539f0904590999d46c75df012b": {
        "image": "?sys32\\wevtutil.exe",
        "command_line": None,
        "children": []
    },
    '683045c417897765931f9c4de5799babaf16b2ab34a6a3a30eb442512c7df6cf': {
        "image": '?sys32\\svchost.exe',
        "command_line": None,
        "children": [
            {
                "image": '?pf86\\microsoft\\edgeupdate\\microsoftedgeupdate.exe',
                "command_line": None,
                "children": []
            }
        ]
    },
    'ca2681bddeb1b3c58f48ab9244d677808317cc73efb553bf6376621456696386': {
        "image": '?sys32\\svchost.exe',
        "command_line": None,
        "children": [
            {
                "image": '?sys32\\wbem\\wmiprvse.exe',
                "command_line": None,
                "children": []
            }
        ]
    },
    '34f75b36eb062dd4e2fceecea864aeb679d15099f6b76d46d9e881cdc0c2565f': {
        "image": '?sys32\\svchost.exe',
        "command_line": None,
        "children": [
            {
                "image": '?pf86\\windowsapps\\microsoft.yourphone_1.22022.180.0_x64__8wekyb3d8bbwe\\yourphone.exe',
                "command_line": None,
                "children": []
            }
        ]
    },
    'd5eaaf0f58b9480f6d77d6f8cc07fc7de6f0100fd9cb20ffffcd4e3755ac2c91': {
        "image": '?sys32\\svchost.exe',
        "command_line": None,
        "children": [
            {
                "image": '?win\\microsoft.net\\framework64\\v4.0.30319\\smsvchost.exe',
                "command_line": None,
                "children": []
            }
        ]
    },
    '9c1ab7458090e539853fc3467a646f6609bfd65562c493123a0a0bbbf8010756': {
        "image": '?sys32\\svchost.exe',
        "command_line": None,
        "children": [
            {
                "image": '?sys32\\mqsvc.exe',
                "command_line": None,
                "children": []
            }
        ]
    },
    'f2917a808064123e3affa565e9bcbe222ed377a586291c5db0c253647c094d44': {
        "image": '?sys32\\svchost.exe',
        "command_line": None,
        "children": [
            {
                "image": '?sys32\\dwm.exe',
                "command_line": None,
                "children": []
            }
        ]
    },
    '31c722814723945f3a75457cc44353b4d3569c6a352af85dccafa182c58ad653': {
        "image": '?sys32\\svchost.exe',
        "command_line": None,
        "children": [
            {
                "image": '?sys32\\fontdrvhost.exe',
                "command_line": None,
                "children": []
            }
        ]
    },
    'eae18f81f6dd53ad84a780d67f1f91c6f8427e2aba53aeb3617e2c6a64ca6731': {
        "image": '?sys32\\svchost.exe',
        "command_line": None,
        "children": [
            {
                "image": '?sys32\\sihost.exe',
                "command_line": None,
                "children": []
            }
        ]
    },
    'aa43ef5d5f78c7017d4ba1ad33b988ca68e2a2635f5010d8c0bc8157816770c2': {
        "image": '?sys32\\ctfmon.exe',
        "command_line": None,
        "children": []
    },
    'f26db097862af031c8a7ab84423f063be7f6e01f50699cdd3bfc23542af6a5b4': {
        "image": '?sys32\\services.exe',
        "command_line": None,
        "children": [
            {
                "image": '?sys32\\svchost.exe',
                "command_line": 'C:\\WINDOWS\\System32\\svchost.exe -k netsvcs -p -s BITS',
                "children": []
            }
        ]
    },
    '44e862ebd67cd7ffe848064c41aa16111ec0d95c918bb792d1625df1d98b29aa': {
        "image": '?sys32\\smss.exe',
        "command_line": None,
        "children": []
    },
    '1851240177eab8d1db9cae2a230ba8f46f660b99de4324457bfad2b51346bef5': {
        "image": '?sys32\\svchost.exe',
        "command_line": None,
        "children": [
            {
                "image": '?sys32\\searchfilterhost.exe',
                "command_line": None,
                "children": []
            }
        ]
    },
    '444f02be8905f4dc7be2ab190159644baebab2bd8ed351ceb6474ce317440f0c': {
        "image": '?sys32\\svchost.exe',
        "command_line": None,
        "children": [
            {
                "image": '?sys32\\searchprotocolhost.exe',
                "command_line": None,
                "children": []
            }
        ]
    },
    '8c173d9b81725561674d18ec4e7c77d21f93b19384b342fbdf1592f5fc6300f3': {
        "image": '?sys32\\svchost.exe',
        "command_line": None,
        "children": [
            {
                "image": '?sys32\\taskhost.exe',
                "command_line": None,
                "children": []
            }
        ]
    }
}
