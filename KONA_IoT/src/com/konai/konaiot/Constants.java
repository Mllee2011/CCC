package com.konai.konaiot;

import javacard.framework.ISO7816;

public class Constants {
	
    public static final byte OK = (byte) 0x5A;
    public static final byte NOK = (byte) 0xA5;
    public static final short S_OK = (short) 0x5A5A;
    public static final short S_NOK = (short) 0xA5A5;
	//Constants
    public static final short LEN_OID = (short) 0x02;
    public static final short LEN_OBJECT_LENGTH = (short) 0x02;
    public static final short LEN_ALC = (short) 0x03;
    public static final short LEN_OBJECT_HEAD = LEN_OID+LEN_OBJECT_LENGTH+LEN_ALC;
    public static final short LEN_SHA256 = (short)32;
    
    
    
	
	//application life cycle
    public static final byte STATE_ACTIVE = (byte) 0x00;
    public static final byte STATE_INACTIVE = (byte) 0x01;
    public static final byte STATE_PERSO  = (byte) 0x02;
    
    //data status
    public static final byte STATUS_VALID = (byte) 0x5A;
    public static final byte STATUS_DELETED = (byte) 0xA5;
    
    public static final byte DEFAULT_POLICY_KEY_READ = (byte)0x00;
    public static final byte DEFAULT_POLICY_KEY_WRITE =(byte)0x00;
    public static final byte DEFAULT_POLICY_KEY_DELETE =(byte)0x00;
     
    //data structure
    public static final byte OFF_APDU_OBJECT_ID = (byte)(ISO7816.OFFSET_CDATA + 0x00);
    public static final byte OFF_APDU_OBJECT_LENGTH = (byte)(ISO7816.OFFSET_CDATA + 0x02);
    
    public static final byte OFF_APDU_OBJECT_ACL = (byte)(ISO7816.OFFSET_CDATA + 0x04);
    public static final byte OFF_APDU_OBJECT_DATA = (byte)(ISO7816.OFFSET_CDATA + 0x07);

    
    // INS codes
    public static final byte INS_SELECT_AID = (byte) 0xA4;
    public static final byte INS_GET_RANDOM = (byte) 0x84;
    public static final byte INS_INITIALIZE_UPDATE = (byte) 0x50;
    public static final byte INS_EXTERNAL_AUTHENTICATE = (byte) 0x82;
    public static final byte INS_SE_SESSION = (byte) 0x10;
    public static final byte INS_STORE_DATA = (byte) 0xE2;
    public static final byte INS_PUT_KEY = (byte) 0xD8;
    public static final byte INS_GENERATE_KEYPAIR = (byte) 0x46;
    public static final byte INS_SIGN_CDATA = (byte) 0x2A;
    public static final byte INS_GET_DATA = (byte) 0xCA;
    public static final byte INS_SET_LOCK_STATE = (byte) 0xF4;
    public static final byte INS_COMPACT_STORAGE = (byte) 0xFE;
    public static final byte INS_ENCRYPT_DECRYPT = (byte) 0xB0;
    public static final byte INS_GET_RESPONSE = (byte) 0xC0;
    
    public static final byte INS_VERIFY_SIGNATURE = (byte) 0x20;

    //P1 
    public static final byte P1_VERIFY_ECDSA = (byte) 0x00;
    
    //SW
    public static final short SW_SIGNATURE_INVALID = (short) 0x6988;
    public static final short SW_ECC_KEY_NOT_INITIALIZED  = (short)0x6880;

    //tag value
    public static final byte TAG_SRVR_RANDOM    	  = (byte) 0x83;
    public static final byte TAG_SERVER_PUBKEY_ID        = (byte) 0x84;
    public static final byte TAG_HASH_DATA  		  = (byte) 0x85;
    public static final byte TAG_SIGNATURE_DATA       = (byte) 0x86;
    
    //parameter
    public static final short RECORD_NUMBER =(byte)30;
    public static final short KEY_NUMBER =(byte)30;
    
    
    public static final short LEN_BUF_CERT = (short)(1500);
    
    
    
    //TransientData OFFSET 
    public static final short OFF_SM_DATA = (short) 0x00;
    public static final short LEN_SM_STATE = (short)1;
 
    public static final short OFF_OBJECT_REMAIN_SIZE = (short) OFF_SM_DATA+LEN_SM_STATE;
    public static final short LEN_OBJECT_SIZE = (short)2;
    
    public static final short OFF_OFF_RESPONSE_START = (short) OFF_OBJECT_REMAIN_SIZE+LEN_OBJECT_SIZE;
    public static final short LEN_OFF_RESPONSE_START = (short)2;
    
    public static final short OFF_RNG_LENGTH = (short) OFF_OFF_RESPONSE_START+LEN_OFF_RESPONSE_START;
    public static final short LEN_RNG_LENGTH = (short)1;
    
    public static final short OFF_RNG_DATA = (short) OFF_RNG_LENGTH+LEN_RNG_LENGTH;
    public static final short LEN_RNG_DATA = (short)32;
    
    public static final short TRANSIENT_DATA_SIZE = (short)(OFF_RNG_DATA + LEN_RNG_DATA);
    
    
}
