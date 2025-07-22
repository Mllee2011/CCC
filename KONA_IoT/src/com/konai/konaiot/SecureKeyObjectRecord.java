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
    public static short search(SecureKeyObjectRecord[] keys, short allocated_records, short objectId) {
        for (short i = 0; i < allocated_records; i++) {
            SecureKeyObjectRecord reckey = keys[i];
            if (reckey != null && reckey.objectId == objectId && reckey.status == Constants.STATUS_VALID) {
                return i;
            }
        }
        return (short)0xFFFF;
    }

	public void uninstall() {
		keyObject = null;
		acl = null;
	    status =0;
	    objectId=0;
	}
}
