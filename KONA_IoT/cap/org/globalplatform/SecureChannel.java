package org.globalplatform;
import javacard.framework.Shareable;
public interface SecureChannel extends Shareable {
short processSecurity(javacard.framework.APDU param1);
short wrap(byte[] param1, short param2, short param3);
short unwrap(byte[] param1, short param2, short param3);
short decryptData(byte[] param1, short param2, short param3);
short encryptData(byte[] param1, short param2, short param3);
void resetSecurity();
byte getSecurityLevel();
}
