# NOTE

- these are the drivers from HP's website
- HP Spectre x360 16 inch 2-in-1 Laptop PC 16-f2000
    - SP148234 contains version 6.0.62.1111 Rev.B
    - SP144106 contains version 6.0.62.1111 Rev.A (missing here)
- HP Spectre x360 16 inch 2-in-1 Laptop PC 16-f1000
    - SP141455 contains version 6.0.59.1111 Rev.B (the one used in Ghidra)
    - SP132990 contains version 6.0.49.1111

- Debug paths (I did not find a better place for them)
    - if we open (e.g. with pestudio and section indicators) any dll or exe from the driver we find these filenames for debug
    - SP148234
        - D:\Jenkins\workspace\HPCNB-111_Pipeline_22H2\HDRFP-8405\sw\niseWrappers\wbf\adapters\synaFpAdapter\x64\Release\OutDirUwp\synaFpAdapter111.pdb
        - D:\Jenkins\workspace\HPCNB-111_Pipeline_22H2\HDRFP-8405\sw\niseWrappers\wbf\wbdi\driver\x64\x64\Release\OutDirUwp\synaWudfBioUsb111.pdb
    - SP141455
        - D:\Jenkins\workspace\HPCNB-111_Pipeline_sgx\HDRFP-7900\sw\niseWrappers\wbf\adapters\synaFpAdapter\x64\Release\OutDirUwp\synaFpAdapter111.pdb
        - D:\Jenkins\workspace\HPCNB-111_Pipeline_sgx\HDRFP-7900\sw\niseWrappers\wbf\services\WBFResetService\x64\Release\WBFResetService111.pdb
        - D:\Jenkins\workspace\HPCNB-111_Pipeline_sgx\HDRFP-7900\sw\niseWrappers\wbf\wbdi\driver\x64\x64\Release\OutDirUwp\synaWudfBioUsb111.pdb


