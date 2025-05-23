package com.konai.konaiot;

public class SecureObjectRecord {

    public byte status;
    public short objectId;
    public byte[] acl = new byte[3];
    public short dataLength;
    public byte[] data;

    public static short search(SecureObjectRecord[] records, short allocated_records, short objectId) {
        for (short i = 0; i < allocated_records; i++) {
            if (records[i] != null && records[i].objectId == objectId && records[i].status == Constants.STATUS_VALID) {
                return i;
            }
        }
        return (short) 0xFFFF;
    }
}