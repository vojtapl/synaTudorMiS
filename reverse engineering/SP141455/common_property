# SET
    vfmStgSetCommonProperty >>>>>>>>
        stiTudorSetCommonProperty >>>>>>>>
            _GetCommonPropUsrObjId >>>>>>>>
1. tudorCmdGetObjectList
    - msg:
        - data:
                9f 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    - resp:
          00 00 00 00
    - creating common property user object
    - VCSFW_CMD_DB2_WRITE_OBJECT
        - msg data:
            a2 01 01 00 00 01 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00
        - resp data:
            00 00 00 00 c7 14 2a 7e 7d 8a 6b 9f e3 b1 33 62
            2a 81 8c 03

            cmdId:
            edx=9f
            sendBlobLen:
            000000eb`5127f3c0  00000015
            sendBlobData:
            00000230`cf0d5400  9f 03 00 00 00 c7 14 2a-7e 7d 8a 6b 9f e3 b1 33  .......*~}.k...3
            00000230`cf0d5410  62 2a 81 8c 03                                   b*...
            CMD SEND: VCSFW_CMD_DB2_GET_OBJECT_LIST

            tudorSecureBioConnect RECV
            recvBlobLen:
            000000eb`5127f430  00000004
            recvBlobData:
            00000230`cf090210  00 00 00 00                                      ....
            CMD REPLY: VCSFW_CMD_DB2_GET_OBJECT_LIST
            serializeProperty
            palTagValContainerInit
            palTagValSetBlobDataProperty
            SetPropertyPriv
            SetPropertyPriv
            param_2
            edx=1
            tagIdx
            r8w=4
            get0_set1
            r9d=1
            param_5
            000000eb`5127f490  0000
            blobSize
            000000eb`5127f498  0002
            blobData
            000000eb`5127f5d4  18 01                                            ..
            palTagValSetBlobDataProperty
            SetPropertyPriv
            SetPropertyPriv
            param_2
            edx=1
            tagIdx
            r8w=5
            get0_set1
            r9d=1
            param_5
            000000eb`5127f490  0000
            blobSize
            000000eb`5127f498  009a
            blobData
            00000230`cf07d6b0  03 00 94 00 00 00 30 00-34 00 37 00 65 00 66 00  ......0.4.7.e.f.
            00000230`cf07d6c0  64 00 62 00 34 00 2d 00-33 00 39 00 35 00 65 00  d.b.4.-.3.9.5.e.
            00000230`cf07d6d0  2d 00 34 00 38 00 62 00-30 00 2d 00 38 00 35 00  -.4.8.b.0.-.8.5.
            00000230`cf07d6e0  34 00 36 00 2d 00 37 00-62 00 35 00 61 00 34 00  4.6.-.7.b.5.a.4.
            00000230`cf07d6f0  30 00 36 00 39 00 35 00-35 00 37 00 31 00 00 00  0.6.9.5.5.7.1...
            00000230`cf07d700  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
            00000230`cf07d710  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
            00000230`cf07d720  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
            00000230`cf07d730  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
            00000230`cf07d740  00 00 00 00 00 00 00 00-00 00                    ..........
            palTagValGetBlobDataProperty
            palTagValGetBlobDataProperty
            free_hContainter
            tudorCmdWriteObject
            allocateFWToSend
            execute_firmware_command
            tudorIoctl
            tudorIoctl opCode: (3 -> send any command)
            tudorSendAnyCommand
            tudorSecureBioConnect

            tudorSecureBioConnect SEND
            cmdId:
            edx=a2
            sendBlobLen:
            000000eb`5127f450  000000cd
            sendBlobData:
            00000230`cf0b3ab0  a2 03 01 00 00 c7 14 2a-7e 7d 8a 6b 9f e3 b1 33  .......*~}.k...3
            00000230`cf0b3ac0  62 2a 81 8c 03 00 00 00-00 00 00 00 00 a8 00 00  b*..............
            00000230`cf0b3ad0  00 04 00 02 00 00 00 18-01 05 00 9a 00 00 00 03  ................
            00000230`cf0b3ae0  00 94 00 00 00 30 00 34-00 37 00 65 00 66 00 64  .....0.4.7.e.f.d
            00000230`cf0b3af0  00 62 00 34 00 2d 00 33-00 39 00 35 00 65 00 2d  .b.4.-.3.9.5.e.-
            00000230`cf0b3b00  00 34 00 38 00 62 00 30-00 2d 00 38 00 35 00 34  .4.8.b.0.-.8.5.4
            00000230`cf0b3b10  00 36 00 2d 00 37 00 62-00 35 00 61 00 34 00 30  .6.-.7.b.5.a.4.0
            00000230`cf0b3b20  00 36 00 39 00 35 00 35-00 37 00 31 00 00 00 00  .6.9.5.5.7.1....
            00000230`cf0b3b30  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
            00000230`cf0b3b40  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
            00000230`cf0b3b50  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
            00000230`cf0b3b60  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
            00000230`cf0b3b70  00 00 00 00 00 00 00 00-00 00 00 00 00           .............
            CMD SEND: VCSFW_CMD_DB2_WRITE_OBJECT

            tudorSecureBioConnect RECV
            recvBlobLen:
            000000eb`5127f4d8  00000014
            recvBlobData:
            00000230`cf06cbd0  00 00 00 00 38 82 87 ed-56 d7 20 03 fe f9 2b ff  ....8...V. ...+.
            00000230`cf06cbe0  ed aa f0 9e                                      ....
            CMD REPLY: VCSFW_CMD_DB2_WRITE_OBJECT
        stiTudorSetCommonProperty <<<<<<<<

