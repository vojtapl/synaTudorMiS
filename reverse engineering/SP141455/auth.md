# CMDs:
1. misGetAuthImageMetrics
    - cmd ID is 0x9d - get image quality with metrics 0x10000
    - works
    - if quality is lower than 50 discard
2. misAuthImageToTemplates
    - cmd ID is 0x99
    - request (they all seem to be the same):
        - len: 0xd
        - data:
            0 (cmd ID): 99
            1-4: 01 00 00 00
            5-8: 00 00 00 00
            9-12: 00 00 00 00
        - so nothing is given
    - response on match fail:
        - len: 0x2
        - 0-1 (status): 09 05 aka error code of no match
    - response on match success:
        - len: 0xb1
        - data:
            0-1 (status): 00 00
            2-17 (tuid): bd 2e 50 c4 67 63 0a c1 3f 37 29 83 7f 03 27 da
            18-21 (qm_struct_size): 24 00 00 00 - matches 36
            22-25 (recvData_y size): 00 00 00 00
            26-29 (recvData_z size): 6f 00 00 00
            30-65 (match stats):
                0-3 (match score): 91 0a 00 00
                4-: fc 31 03 00 eb e3 0c 00 fb fc 00 00 c2 d8 ff ff
                20-23: 01 00 00 00
                24-: 03 00 00 00
                28-31: 09 00 00 00
                32-: 00 00 00 00
            66- (data_y):
                - tag0: tuid - the one from finishing enrollment
                    - number: 00 00
                    - len: 10 00 00 00
                    - data: bd 2e 50 c4 67 63 0a c1 3f 37 29 83 7f 03 27 da
                - tag1: - matches *userId* aka tag 1 from _tudorCmdMisEnrollCommit                    - number: 01 00
                    - len: 4c 00 00 00
                    - data:
                        03 00 00 00 1c 00 00 00 01 05 00 00 00 00 00 05
                        15 00 00 00 0c bb 01 4e 6d dd 74 eb 5b 41 eb 98
                        e9 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                        00 00 00 00 00 00 00 00 00 00 00 00
                - tag2: subId - matches *subId* aka tag 2 from _tudorCmdMisEnrollCommit
                    - number: 02 00
                    - len: 01 00 00 00
                    - data: f5
                - tag3: ???
                    - number: 3
                    -> missing
    - SetPropertyPriv - tuid
        param_2 = 0
        tagIdx = 0
        get0_set1 = 0
        param_5 = 1
        blobSize = 0x10
        blobData: bd 2e 50 c4 67 63 0a c1 3f 37 29 83 7f 03 27 da
    - SetPropertyPriv - userId
        - param_2: 0
        - tagIdx: 1
        - get0_set1: 0
        - param_5: 000000c30001
        - blobSize: 004c
        - blobData:
            03 00 00 00 1c 00 00 00 01 05 00 00 00 00 00 05
            15 00 00 00 0c bb 01 4e 6d dd 74 eb 5b 41 eb 98
            e9 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00
    - SetPropertyPriv - subId
        - param_2: 0
        - tagIdx: 2
        - get0_set1: 0
        - param_5: 0001
        - blobSize: 0001
        - blobData:  f5
3. _updateEnrollmentCache
    - TODO: after successfull authentication

