# CMDs


?. misEnrollAddImage
    - sent:
        - cmdId: 0x96
        - len: 00000005
        - data:
            0 (cmd): 96
            1-4 (type): 02 00 00 00
    - response:
        - len: 0x52
        - data:
            0-1 (status): 00 00
            2-17 (tuid): bd 2e 50 c4 67 63 0a c1 3f 37 29 83 7f 03 27 da
            18-21 (len of data): 3c 00 00 00
            22- (data):
                0-1: ff 03
                2-3 (progress): 64 00
                4-: 44 96 78 d9 5f 99 61 96 5f eb 93 eb 04 fd 9a 5e
                20-23 (quality): 51 00 00 00
                24-27 (redundant): 00 00 00 00
                28-31 (rejected): 00 00 00 00
                32-: bc 9b 00 00
                26-39 (template count): 0a 00 00 00
                40-41 (enroll quality): 4e 00
                42-: 70 60 00 00 00 00
                48-51 (status): 00 00 00 00
                4-: 52- 05 00 00 00
                56-59: 00 00 00 00

?+1. stiTudorAddEnrollment
    - _serializePayload
        - SetPropertyPriv
            - param_2: 1
            - tagIdx: 0
            - get0_set1: 1
            - param_5: 0000
            - blobSize: 0010
            - blobData:
                44 96 78 d9 5f 99 61 96 5f eb 93 eb 04 fd 9a 5e
        - SetPropertyPriv
            - param_2: 1
            - tagIdx: 1
            - get0_set1: 1
            - param_5: 0000
            - blobSize: 004c
            - blobData
                03 00 00 00 1c 00 00 00 01 05 00 00 00 00 00 05
                15 00 00 00 0c bb 01 4e 6d dd 74 eb 5b 41 eb 98
                e9 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00
        - SetPropertyPriv
            - param_2: 1
            - tagIdx: 2
            - get0_set1: 1
            - param_5 0000
            - blobSize: 0001
            - blobData:
                 f5
    - _tudorCmdMisEnrollCommit
        - send:
            - cmdId: 0x96
            - sendBlobLen: 0x7c
            - sendBlobData:
                0 (cmd): 96
                1-4: 03 00 00 00
                5-8: 00 00 00 00
                9-12 (enrollment commit data size): 6f 00 00 00
                13- (enrollment commit data):
                    - tag 0:
                        - number: 00 00
                        - len: 10 00 00 00
                        - data: 44 96 78 d9 5f 99 61 96 5f eb 93 eb 04 fd 9a 5e
                    - tag 1:
                        - number: 01 00
                        - len: 4c 00 00 00
                        - data:
                            - ?: 03 00 00 00
                            - matches len of account sid: 1c 00 00 00
                            - account sid: 01 05 00 00 00 00 00 05 15 00 00 00 0c bb 01 4e
                                           6d dd 74 eb 5b 41 eb 98 e9 03 00 00
                            - padding: 00 00 00 00 00 00 00 00 00 00 00 00
                                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                                       00 00 00 00 00 00 00 00 00 00 00 00
                    - tag 2:
                        - number: 02 00
                        - len: 01 00 00 00
                        - data: f5
        - response:
            - recvBlobLen: 2
            - recvBlobData:
                00 00

?+2. _updateEnrollmnetCache
    1. send VCSFW_CMD_DB2_GET_DB_INFO and store current numbers of users, templates, payloads
    2. send VCSFW_CMD_DB2_GET_OBJECT_LIST and get template list with:
        - msg:
            0 (cmd ID): 9f
            1-4 (type): 02 00 00 00
            5-19 (id): ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
    3. for each template id send VCSFW_CMD_DB2_GET_OBJECT_LIST and get payload list
        -> for each payload send VCSFW_CMD_DB2_GET_OBJECT_INFO to get size of received data
            - resp:
                0-1 (status): 00 00
                2-3: 00 00
                4-19 (some part of host certifiacte): 4d 63 1a 68 a5 8d 4c ff 6f d2 ef 97 78 09 e8 2f
                20-33 (tuid): 44 96 78 d9 5f 99 61 96 5f eb 93 eb 04 fd 9a 5e
                34-37: 0c 00 00 00
                38-41: 00 00 00 00
                42-45: 02 00 00 00
                46-49 (size): 83 00 00 00
        -> then VCSFW_CMD_DB2_GET_OBJECT_DATA
            - resp:
                0-1 (status): 00 00
                2-3: 00 00
                4-7 (obj size): 6f 00 00 00
                    - tag 0: tuid
                        - num: 00 00
                        - len: 10 00 00 00
                        - data:
                            44 96 78 d9 5f 99 61 96 5f eb 93 eb 04 fd 9a 5e
                    - tag 1: userid
                        - num: 01 00
                        - len: 4c 00 00 00
                        - data:
                            03 00 00 00 1c 00 00 00 01 05 00 00 00 00 00 05
                            15 00 00 00 0c bb 01 4e 6d dd 74 eb 5b 41 eb 98
                            e9 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                            00 00 00 00 00 00 00 00 00 00 00 00
                    - tag 2: subid
                        - num: 02 00
                        - len: 01 00 00 00
                        - data:
                            f5
?. misEnrollFinish
    - msg:
        - cmd ID: 0x96
        - sendBlobLen:
            00000005
        - sendBlobData:
            96 04 00 00 00
    - resp:
        - len: 0x2
        - data:
            00 00

