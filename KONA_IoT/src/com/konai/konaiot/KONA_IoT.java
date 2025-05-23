package com.konai.konaiot;

import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.AppletEvent;
import javacard.framework.CardRuntimeException;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.DESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;

/** 
 * KONA_IoT <br>
 * 
 *  @author mllee
 *
 */

// APPLET : 0F4B4F4E41
//        : 0F4B4F4E4101

public class KONA_IoT extends Applet implements AppletEvent {
	
	private static byte intanceNO = (byte)0x00;
	private static byte[] TransientData;
	private static RandomData rng;
	private static SecureChannel gpSecureChannel;
	
	protected static byte[] buf_tmp;
	
	
	private byte currentPhase = Constants.STATE_INACTIVE;
	private short allocated_records;
	private short allocated_keys;
	
	private SecureObjectRecord[] records;
	private SecureKeyObjectRecord[] keys;
	
	public void uninstall() {
		if(intanceNO == (byte)0x01){
			
			rng = null;
			TransientData = null;
			records = null;
			keys = null;
			gpSecureChannel =null;
			buf_tmp = null;
			
			intanceNO = (byte)0;
		}else{
			intanceNO--;
		}
	}

	public KONA_IoT(byte[] bArray, short bOffset){
		
		//install parameter offset
		short offset = (short)(bOffset + bArray[bOffset] + bArray[(short)(bOffset+bArray[bOffset]+1)] + 2);
		
		switch(bArray[offset]){
			case 0:// C9 00 
				break;
			default:
				ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		if(TransientData == null){
			TransientData = JCSystem.makeTransientByteArray(Constants.TRANSIENT_DATA_SIZE, JCSystem.CLEAR_ON_DESELECT)					;
			buf_tmp			= JCSystem.makeTransientByteArray(Constants.LEN_BUF_CERT, JCSystem.CLEAR_ON_DESELECT);
			rng =  RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		}
		
		records = new SecureObjectRecord[Constants.RECORD_NUMBER];
		keys = new SecureKeyObjectRecord[Constants.KEY_NUMBER];
		
		allocated_records =0;
		allocated_keys = 0;
		
		setPhase(Constants.STATE_PERSO);// set phase perso_data
		intanceNO++;
		
		
	}
	
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new KONA_IoT(bArray, bOffset).register(bArray, (short) (bOffset + 1),
				bArray[bOffset]);
	}


	
	public void process(APDU apdu) {
		
		byte[] apduBuffer = apdu.getBuffer();
		byte ins = apduBuffer[ISO7816.OFFSET_INS];

		apduBuffer[ISO7816.OFFSET_CLA] &= (byte)0xFC; 		
		try{
			if (ins == Constants.INS_SELECT_AID){  
				IoT_select(apdu, apduBuffer);
				return;
			}
			switch (ins) {
	        case Constants.INS_GET_RANDOM:
	            IoT_getRandom(apdu, apduBuffer);
	            break;
	        case Constants.INS_INITIALIZE_UPDATE:
	            // TODO SCP03
	        	GP_initalizeupdate_02(apdu, apduBuffer);
	            break;
	        case Constants.INS_EXTERNAL_AUTHENTICATE:
	            // TODO SCP03
	        	GP_externalauthenticate_02(apdu, apduBuffer);
	            break;
	        case Constants.INS_SE_SESSION:
	            // handleSESession(apdu);
	            break;
	        case Constants.INS_GENERATE_KEYPAIR:
	        	IoT_generateKeyPair(apdu, apduBuffer);
	            break;
	        case Constants.INS_PUT_KEY:
	        	IoT_putKey(apdu, apduBuffer);
	            break;
	        case Constants.INS_SIGN_CDATA:
	            // IoT_signData(apdu, apduBuffer);
	            break;
	        case Constants.INS_VERIFY_SIGNATURE:
	            // IoT_verifySignature(apdu, apduBuffer);
	            break;
	        case Constants.INS_STORE_DATA:
	        	IoT_storeData(apdu, apduBuffer);
	            break;
	        case Constants.INS_GET_DATA:
	        	IoT_getData(apdu, apduBuffer);
	            break;
	        case Constants.INS_SET_LOCK_STATE:
	            //IoT_setLockState(apdu, apduBuffer);
	            break;
	        case Constants.INS_COMPACT_STORAGE:
	        	//IoT_compactStorage();
	            break;
	        case Constants.INS_GET_RESPONSE:
	        	IoT_getResponse(apdu, apduBuffer);
	            break;    
			
				default:
				
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			}
		}catch (ISOException e) {
			ISOException.throwIt(e.getReason());
		}
	}

	private void IoT_generateKeyPair(APDU apdu,byte[] apduBuffer) {
	    byte keyType  = apduBuffer[ISO7816.OFFSET_P1];   // 0x01=ECC, 0x02=RSA
	    //byte keyUsage = apduBuffer[ISO7816.OFFSET_P2];   // e.g. 0x10=Signature,0x11=ECDH
	    short lc      = apdu.setIncomingAndReceive();
	    if (lc != 7) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

	    short keyDataLen = (short)(Util.getShort(apduBuffer, (short)(Constants.OFF_APDU_OBJECT_LENGTH))-Constants.LEN_ALC);
	    
	    short bitLen = (short)(keyDataLen * 8);
	    
	    //byte[] acl = new byte[3];
	    //Util.arrayCopy(apduBuffer, offset, acl, (short)0, (short)3);

	    KeyPair kp;
	    Key keyPubObj;
	    Key keyPriObj;
	    short outLen;

	    switch (keyType) {
	        case (byte)0x01:
	            kp = new KeyPair(KeyPair.ALG_EC_FP, bitLen);
	            ECPrivateKey ecPriv = (ECPrivateKey) kp.getPrivate();
	            ECPublicKey  ecPub  = (ECPublicKey)  kp.getPublic();
	            Secp256r1.setCommonCurveParameters(ecPriv);
	            Secp256r1.setCommonCurveParameters(ecPub);
	            kp.genKeyPair();
	            keyPriObj = ecPriv;
	            keyPubObj = ecPub;	            
	            SecureKeyObjectRecord recE = new SecureKeyObjectRecord();
	            recE.status    = Constants.STATUS_VALID;
	            recE.objectId  = Util.getShort(apduBuffer, Constants.OFF_APDU_OBJECT_ID);;
	            Util.arrayCopy(apduBuffer, (short)Constants.OFF_APDU_OBJECT_ACL, recE.acl, (short)0, (short)3);
	            recE.keyObject = keyPriObj;
	            keys[allocated_keys++] = recE;
	            
	            apdu.setOutgoing();
	            outLen = ecPub.getW(apduBuffer, (short)0);
	            apdu.setOutgoingLength(outLen);
	            apdu.sendBytes((short)0, outLen);
	            return;

	        case (byte)0x02:
	            kp = new KeyPair(KeyPair.ALG_RSA_CRT, bitLen);
	            RSAPrivateKey rsaPriv = (RSAPrivateKey) kp.getPrivate();
	            RSAPublicKey  rsaPub  = (RSAPublicKey)  kp.getPublic();
	            kp.genKeyPair();
	            keyPriObj = rsaPriv;
	            keyPubObj = rsaPub;
	            SecureKeyObjectRecord recR = new SecureKeyObjectRecord();
	            recR.status    = Constants.STATUS_VALID;
	            recR.objectId  = Util.getShort(apduBuffer, Constants.OFF_APDU_OBJECT_ID);
	            Util.arrayCopy(apduBuffer, (short)Constants.OFF_APDU_OBJECT_ACL, recR.acl, (short)0, (short)3);
	            recR.keyObject = rsaPriv;
	            keys[allocated_keys++] = recR;
	            
	            
	            apdu.setOutgoing();
	            outLen = rsaPub.getModulus(apduBuffer, (short)0);
	            apdu.setOutgoingLength(outLen);
	            apdu.sendBytes((short)0, outLen);
	            return;

	        default:
	            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
	    }
	    return;
	}

	
	
	private void IoT_putKey(APDU apdu,byte[] apduBuffer) {
	    // 1) Paramter
	    byte keyType  = apduBuffer[ISO7816.OFFSET_P1];
	    short lc      = apdu.setIncomingAndReceive();

	    if (allocated_records >= Constants.KEY_NUMBER) {
	        ISOException.throwIt(ISO7816.SW_FILE_FULL);
	    }
	    
	    short keyDataLen = (short)(Util.getShort(apduBuffer, (short)(Constants.OFF_APDU_OBJECT_LENGTH))-Constants.LEN_ALC);
	    short bitLen = (short)(keyDataLen * 8);
	    
	    Key keyObj;
	    switch (keyType) {
	        case (byte)0x01: // ECC private
	            ECPrivateKey ecPriv = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, bitLen, false);
	            Secp256r1.setCommonCurveParameters(ecPriv);
	            ecPriv.setS(apduBuffer, Constants.OFF_APDU_OBJECT_DATA, keyDataLen);
	            keyObj = ecPriv;
	            break;

	        case (byte)0x11: // ECC public
	            ECPublicKey ecPub = (ECPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
	            Secp256r1.setCommonCurveParameters(ecPub);
	            ecPub.setW(apduBuffer, Constants.OFF_APDU_OBJECT_DATA , keyDataLen);
	            keyObj = ecPub;
	            break;

	        case (byte)0x02: // RSA private
	            // keyData |modulus|exponent|
	            RSAPrivateKey rsaPriv = (RSAPrivateKey)
	              KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, bitLen, false);
	            // modulus/exponent
	            rsaPriv.setModulus(apduBuffer,Constants.OFF_APDU_OBJECT_DATA, (short)(keyDataLen/2));
	            rsaPriv.setExponent(apduBuffer, (short)(keyDataLen/2), (short)(keyDataLen/2));
	            keyObj = rsaPriv;
	            break;

	        case (byte)0x12: // RSA public
	            RSAPublicKey rsaPub = (RSAPublicKey)
	              KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, bitLen, false);
	            //  modulus/exponent
	            rsaPub.setModulus(apduBuffer,Constants.OFF_APDU_OBJECT_DATA, (short)(keyDataLen/2));
	            rsaPub.setExponent(apduBuffer, (short)(keyDataLen/2), (short)(keyDataLen/2));
	            keyObj = rsaPub;
	            break;

	        case (byte)0x03: // AES
	            if (bitLen != 128 && bitLen != 192 && bitLen != 256) {
	                ISOException.throwIt((short)0x6A80);
	            }
	            AESKey aesKey = (AESKey)
	              KeyBuilder.buildKey(KeyBuilder.TYPE_AES, bitLen, false);
	            aesKey.setKey(apduBuffer,Constants.OFF_APDU_OBJECT_DATA);
	            keyObj = aesKey;
	            break;

	        case (byte)0x04: // 3DES
	            DESKey des3Key = (DESKey)
	              KeyBuilder.buildKey(KeyBuilder.TYPE_DES,bitLen, false);
	            des3Key.setKey(apduBuffer,Constants.OFF_APDU_OBJECT_DATA);
	            keyObj = des3Key;
	            break;

	        case (byte)0x05: // DES
	            DESKey desKey = (DESKey)
	              KeyBuilder.buildKey(KeyBuilder.TYPE_DES, bitLen, false);
	            desKey.setKey(apduBuffer,Constants.OFF_APDU_OBJECT_DATA);
	            keyObj = desKey;
	            break;

	        default:
	            ISOException.throwIt((short)0x6A80);
	            return;
	    }

	    // 6) store data 
	    SecureKeyObjectRecord rec = new SecureKeyObjectRecord();
	    rec.status    = Constants.STATUS_VALID;
	    rec.objectId  = Util.getShort(apduBuffer,Constants.OFF_APDU_OBJECT_DATA);
	    Util.arrayCopy(apduBuffer, Constants.OFF_APDU_OBJECT_ACL, rec.acl, (short)0, (short)3);
	    rec.keyObject = keyObj;
	    keys[allocated_keys++] = rec;

	    return;
	}

	private void GP_initalizeupdate_02(APDU apdu,byte[] apduBuffer) {
		// TODO Auto-generated method stub
		apdu.setIncomingAndReceive();
		try {
			gpSecureChannel = GPSystem.getSecureChannel();
			apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, gpSecureChannel.processSecurity(apdu));
			
		} catch (CardRuntimeException cre) {
			// Open Secure Channel failed
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		
		return;
	}
	public void GP_externalauthenticate_02(APDU apdu,byte[] apduBuffer)  {
		
		apdu.setIncomingAndReceive();
		
		gpSecureChannel.processSecurity(apdu);
		
		return;
	}

	private void IoT_getRandom(APDU apdu,byte[] apduBuffer) {
		// TODO Auto-generated method stub
	    short lc = (short)(apduBuffer[ISO7816.OFFSET_LC]&0x00FF);
	    
	    rng.generateData(apduBuffer, (short) 0, lc);
	    TransientData[Constants.OFF_RNG_LENGTH] = (byte) lc;
	    Util.arrayCopyNonAtomic(apduBuffer, (short) 0, TransientData, Constants.OFF_RNG_DATA, lc);
	    

	    apdu.setOutgoing();
	    apdu.setOutgoingLength((byte) lc);
	    apdu.sendBytes((short) 0, lc);

	    return;
	}
	private void IoT_getResponse(APDU apdu,byte[] apduBuffer) {
		// TODO Auto-generated method stub
		short le = apdu.setOutgoing();
		short off_start = (short)(Util.getShort(TransientData, Constants.OFF_OFF_RESPONSE_START));
		short remain =(short)(Util.getShort(TransientData, Constants.OFF_OBJECT_SIZE)-off_start - le);

		if(remain > (short)0){
			apdu.setOutgoingLength(le);
			apdu.sendBytesLong(buf_tmp,(short)off_start, le);
			Util.setShort(TransientData, Constants.OFF_OFF_RESPONSE_START, (short)(off_start+le));
			
			if(remain > (short)0x00FF){
				ISOException.throwIt((short)ISO7816.SW_BYTES_REMAINING_00);
			}else{
				ISOException.throwIt((short)(ISO7816.SW_BYTES_REMAINING_00+remain));
			}
	    }else if(remain ==0){
	    	//reset
	    	Util.arrayFillNonAtomic(TransientData, Constants.OFF_OBJECT_SIZE, (short)4, (byte)0);
	    	apdu.setOutgoingLength(le);
	    	apdu.sendBytesLong(buf_tmp,(short)off_start, le);
	    	return; 
	    //}else ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	    }else ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
		
		
		return;
	}
	
	private void IoT_getData(APDU apdu,byte[] apduBuffer) {
		// TODO Auto-generated method stub
	    short objectId = Util.getShort(apduBuffer, ISO7816.OFFSET_P1);
	    short idx = SecureObjectRecord.search(records, allocated_records, objectId);
	    
	    if (idx == (short) 0xFFFF) {
	        ISOException.throwIt((short) 0x6A88); // Not Found
	    }

	    SecureObjectRecord rec = records[idx];
	    
	    Util.arrayCopyNonAtomic(rec.data, (short) 0, buf_tmp, (short) 0, rec.dataLength);
	    short le = apdu.setOutgoing();
	    short remain = (short)(rec.dataLength - le);
	    if(remain > (short)0){
	    	
	    	Util.setShort(TransientData, Constants.OFF_OBJECT_SIZE,rec.dataLength);
	    	
	    	if(remain > (short)0x00FF){
	    		ISOException.throwIt((short)ISO7816.SW_BYTES_REMAINING_00);
	    	}else{
	    		ISOException.throwIt((short)(ISO7816.SW_BYTES_REMAINING_00+remain));
	    	}
	    }else{
	    	apdu.setOutgoingLength(rec.dataLength);
	    	apdu.sendBytesLong(buf_tmp,(short)0, rec.dataLength);
	    }
	    
	    return;
	}

	private void IoT_storeData(APDU apdu,byte[] apduBuffer) {
		// TODO Auto-generated method stub
	    short lc = (short)(apdu.setIncomingAndReceive()&0x00FF);
	    
	    //short offset = ISO7816.OFFSET_CDATA;
	    byte p2 = apduBuffer[ISO7816.OFFSET_P2];

	    
	    short pendingLength = Util.getShort(TransientData, (short)(Constants.OFF_OBJECT_SIZE));
	    
	    if (pendingLength == 0) {
	        // NEW OBJECT
		    if (allocated_records >= Constants.RECORD_NUMBER) {
		        ISOException.throwIt(ISO7816.SW_FILE_FULL);
		    }
		    SecureObjectRecord rec = new SecureObjectRecord();
		    rec.status = Constants.STATUS_VALID;
		    rec.objectId = Util.getShort(apduBuffer, Constants.OFF_APDU_OBJECT_ID); 
		    rec.dataLength = (short)(Util.getShort(apduBuffer,Constants.OFF_APDU_OBJECT_LENGTH)-Constants.LEN_ALC); 
		    Util.arrayCopy(apduBuffer, Constants.OFF_APDU_OBJECT_ACL, rec.acl, (short) 0, (short)Constants.LEN_ALC); 
		    
	        rec.data = new byte[rec.dataLength];
	        //Object head is 7byte
	        Util.arrayCopy(apduBuffer, Constants.OFF_APDU_OBJECT_DATA, rec.data, (short) 0, (short)(lc-Constants.LEN_OBJECT_HEAD));

	        records[allocated_records] = rec;

	        pendingLength = (short)(rec.dataLength - lc + Constants.LEN_OBJECT_HEAD);
	        
	        Util.setShort(TransientData, (short)(Constants.OFF_OBJECT_SIZE), pendingLength);
	    } else {
	        //store data chaining
	        SecureObjectRecord rec = records[(short)(allocated_records)];

	        short written = (short)(rec.dataLength - pendingLength);

	        if ((short)(written + lc) > rec.dataLength) {
	            //ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	        	ISOException.throwIt(ISO7816.SW_FILE_INVALID);
	        }

	        Util.arrayCopy(apduBuffer, ISO7816.OFFSET_CDATA, rec.data, written, lc);

	        pendingLength = (short)(pendingLength - lc);
	        Util.setShort(TransientData, (short)(Constants.OFF_OBJECT_SIZE), pendingLength);
	    }

	    if (pendingLength == 0) {
	        //store object is finished. 
	        allocated_records++;
	    }
	    
	    return;
	}

	private void setPhase(byte phase)
	{
		TransientData[Constants.OFF_SM_DATA] = phase;
		currentPhase = phase;
	}
	private short checkPhase(byte phase)
	{
		TransientData[Constants.OFF_SM_DATA] = currentPhase;
		
		if (TransientData[Constants.OFF_SM_DATA] != phase)
		{
			return Constants.S_NOK;
		}
		else
		{
			return Constants.S_OK;
		}
	}
	private final short check_user_phase() {
		return checkPhase(Constants.STATE_ACTIVE);
	} // end of check_user_phase

	private short check_state(byte state){
		if(TransientData[Constants.OFF_SM_DATA] == state){
			return Constants.S_OK;
		}
		return Constants.S_NOK;
	}
	private final void IoT_select(APDU apdu, byte[] apduBuffer) throws ISOException{

		IoT_Util.check_CLA(apduBuffer[ISO7816.OFFSET_CLA], (byte)0x00);
		
		if(check_user_phase() == Constants.S_OK){
			
			
			
			return;
		}else{
			//error
			
			
			
			return;
		}
		//Util.arrayCopyNonAtomic(FCI, (byte)0, apduBuffer, (byte)0, (short)FCI.length);
		//apdu.setOutgoingAndSend((byte)0, (short)FCI.length);

	}
}
