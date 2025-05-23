package com.konai.konaiot;

import javacard.security.Key;

/**
 * SecureKeyObjectRecord
 * Records metadata and actual Key object for stored keys
 */
public class SecureKeyObjectRecord {

    public byte status;
    public short objectId;
    public byte[] acl = new byte[3];
    public Key keyObject;

    /**
     * Search for a valid record matching objectId
     * @return index or 0xFFFF if not found
     */
    public static short search(SecureKeyObjectRecord[] records, short allocated_records, short objectId) {
        for (short i = 0; i < allocated_records; i++) {
            SecureKeyObjectRecord rec = records[i];
            if (rec != null && rec.objectId == objectId && rec.status == Constants.STATUS_VALID) {
                return i;
            }
        }
        return (short)0xFFFF;
    }
}
