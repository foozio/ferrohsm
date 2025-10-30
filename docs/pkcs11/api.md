# PKCS#11 API Documentation

This document provides detailed documentation for the PKCS#11 API implementation in FerroHSM.

## Core Concepts

### Sessions
Sessions are the primary means of interacting with the PKCS#11 module. Each session maintains state information including authentication status, active searches, and object handles.

### Objects
Objects represent cryptographic keys, certificates, and other data managed by the PKCS#11 module. Each object has a unique handle and a set of attributes that describe its properties and capabilities.

### Mechanisms
Mechanisms define the cryptographic operations that can be performed with objects. Each mechanism supports specific parameters and has associated security properties.

## Function Reference

### Library Management

#### C_Initialize
Initializes the PKCS#11 library.

```c
CK_RV C_Initialize(CK_VOID_PTR pInitArgs);
```

Parameters:
- `pInitArgs`: Pointer to initialization arguments (may be NULL)

Returns:
- `CKR_OK`: Success
- `CKR_ARGUMENTS_BAD`: Invalid arguments
- `CKR_CRYPTOKI_ALREADY_INITIALIZED`: Library already initialized

#### C_Finalize
Finalizes the PKCS#11 library.

```c
CK_RV C_Finalize(CK_VOID_PTR pReserved);
```

Parameters:
- `pReserved`: Reserved parameter (must be NULL)

Returns:
- `CKR_OK`: Success
- `CKR_ARGUMENTS_BAD`: Invalid arguments

#### C_GetInfo
Retrieves general information about the PKCS#11 library.

```c
CK_RV C_GetInfo(CK_INFO_PTR pInfo);
```

Parameters:
- `pInfo`: Pointer to CK_INFO structure to receive library information

Returns:
- `CKR_OK`: Success
- `CKR_ARGUMENTS_BAD`: Invalid arguments

### Slot and Token Management

#### C_GetSlotList
Obtains a list of slots in the system.

```c
CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount);
```

Parameters:
- `tokenPresent`: CK_TRUE to list only slots with tokens, CK_FALSE for all slots
- `pSlotList`: Pointer to array to receive slot IDs (may be NULL)
- `pulCount`: Pointer to variable containing array size/returned count

Returns:
- `CKR_OK`: Success
- `CKR_ARGUMENTS_BAD`: Invalid arguments
- `CKR_BUFFER_TOO_SMALL`: Buffer too small to hold slot list

#### C_GetSlotInfo
Obtains information about a particular slot.

```c
CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
```

Parameters:
- `slotID`: ID of the slot to query
- `pInfo`: Pointer to CK_SLOT_INFO structure to receive slot information

Returns:
- `CKR_OK`: Success
- `CKR_ARGUMENTS_BAD`: Invalid arguments
- `CKR_SLOT_ID_INVALID`: Invalid slot ID

### Session Management

#### C_OpenSession
Opens a session between an application and a token.

```c
CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
                   CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession);
```

Parameters:
- `slotID`: ID of the slot to open session with
- `flags`: Session flags (CKF_SERIAL_SESSION required)
- `pApplication`: Application-defined pointer (may be NULL)
- `Notify`: Notification callback (may be NULL)
- `phSession`: Pointer to variable to receive session handle

Returns:
- `CKR_OK`: Success
- `CKR_ARGUMENTS_BAD`: Invalid arguments
- `CKR_SLOT_ID_INVALID`: Invalid slot ID
- `CKR_SESSION_COUNT`: Too many sessions open

#### C_CloseSession
Closes a session between an application and a token.

```c
CK_RV C_CloseSession(CK_SESSION_HANDLE hSession);
```

Parameters:
- `hSession`: Handle of the session to close

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle

#### C_CloseAllSessions
Closes all sessions with a token.

```c
CK_RV C_CloseAllSessions(CK_SLOT_ID slotID);
```

Parameters:
- `slotID`: ID of the slot whose sessions to close

Returns:
- `CKR_OK`: Success
- `CKR_SLOT_ID_INVALID`: Invalid slot ID

#### C_GetSessionInfo
Obtains information about a session.

```c
CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
```

Parameters:
- `hSession`: Handle of the session to query
- `pInfo`: Pointer to CK_SESSION_INFO structure to receive session information

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle

#### C_Login
Logs a user into a token.

```c
CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
             CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
```

Parameters:
- `hSession`: Handle of the session to log into
- `userType`: Type of user (CKU_USER or CKU_SO)
- `pPin`: Pointer to PIN
- `ulPinLen`: Length of PIN

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_USER_ALREADY_LOGGED_IN`: User already logged in
- `CKR_PIN_INCORRECT`: Incorrect PIN

#### C_Logout
Logs a user out of a token.

```c
CK_RV C_Logout(CK_SESSION_HANDLE hSession);
```

Parameters:
- `hSession`: Handle of the session to log out of

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_USER_NOT_LOGGED_IN`: No user logged in

### Object Management

#### C_CreateObject
Creates a new object.

```c
CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
                    CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject);
```

Parameters:
- `hSession`: Handle of the session
- `pTemplate`: Pointer to attribute template
- `ulCount`: Number of attributes in template
- `phObject`: Pointer to variable to receive object handle

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_ARGUMENTS_BAD`: Invalid arguments
- `CKR_ATTRIBUTE_READ_ONLY`: Read-only attribute specified
- `CKR_ATTRIBUTE_TYPE_INVALID`: Invalid attribute type
- `CKR_ATTRIBUTE_VALUE_INVALID`: Invalid attribute value

#### C_CopyObject
Copies an object, creating a new object.

```c
CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                  CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                  CK_OBJECT_HANDLE_PTR phNewObject);
```

Parameters:
- `hSession`: Handle of the session
- `hObject`: Handle of the object to copy
- `pTemplate`: Pointer to attribute template for new object
- `ulCount`: Number of attributes in template
- `phNewObject`: Pointer to variable to receive new object handle

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_OBJECT_HANDLE_INVALID`: Invalid object handle

#### C_DestroyObject
Destroys an object.

```c
CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
```

Parameters:
- `hSession`: Handle of the session
- `hObject`: Handle of the object to destroy

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_OBJECT_HANDLE_INVALID`: Invalid object handle

#### C_GetObjectSize
Gets the size of an object in bytes.

```c
CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                     CK_ULONG_PTR pulSize);
```

Parameters:
- `hSession`: Handle of the session
- `hObject`: Handle of the object
- `pulSize`: Pointer to variable to receive object size

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_OBJECT_HANDLE_INVALID`: Invalid object handle

#### C_GetAttributeValue
Obtains the value of one or more object attributes.

```c
CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                         CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
```

Parameters:
- `hSession`: Handle of the session
- `hObject`: Handle of the object
- `pTemplate`: Pointer to attribute template
- `ulCount`: Number of attributes in template

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_OBJECT_HANDLE_INVALID`: Invalid object handle

#### C_SetAttributeValue
Modifies the value of one or more object attributes.

```c
CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                         CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
```

Parameters:
- `hSession`: Handle of the session
- `hObject`: Handle of the object
- `pTemplate`: Pointer to attribute template
- `ulCount`: Number of attributes in template

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_OBJECT_HANDLE_INVALID`: Invalid object handle
- `CKR_ATTRIBUTE_READ_ONLY`: Read-only attribute specified

#### C_FindObjectsInit
Initializes a search for token and session objects.

```c
CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
                       CK_ULONG ulCount);
```

Parameters:
- `hSession`: Handle of the session
- `pTemplate`: Pointer to attribute template (may be NULL)
- `ulCount`: Number of attributes in template

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_ARGUMENTS_BAD`: Invalid arguments

#### C_FindObjects
Continues a search for token and session objects.

```c
CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
                   CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount);
```

Parameters:
- `hSession`: Handle of the session
- `phObject`: Pointer to array to receive object handles
- `ulMaxObjectCount`: Maximum number of object handles to return
- `pulObjectCount`: Pointer to variable to receive actual number returned

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_ARGUMENTS_BAD`: Invalid arguments
- `CKR_OPERATION_NOT_INITIALIZED`: Search not initialized

#### C_FindObjectsFinal
Terminates a search for token and session objects.

```c
CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession);
```

Parameters:
- `hSession`: Handle of the session

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_OPERATION_NOT_INITIALIZED`: Search not initialized

### Key Management

#### C_GenerateKey
Generates a secret key.

```c
CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                   CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                   CK_OBJECT_HANDLE_PTR phKey);
```

Parameters:
- `hSession`: Handle of the session
- `pMechanism`: Pointer to mechanism structure
- `pTemplate`: Pointer to attribute template for new key
- `ulCount`: Number of attributes in template
- `phKey`: Pointer to variable to receive key handle

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_MECHANISM_INVALID`: Invalid mechanism
- `CKR_MECHANISM_PARAM_INVALID`: Invalid mechanism parameters

#### C_GenerateKeyPair
Generates a public-key/private-key pair.

```c
CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                       CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
                       CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
                       CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey);
```

Parameters:
- `hSession`: Handle of the session
- `pMechanism`: Pointer to mechanism structure
- `pPublicKeyTemplate`: Pointer to attribute template for public key
- `ulPublicKeyAttributeCount`: Number of attributes in public key template
- `pPrivateKeyTemplate`: Pointer to attribute template for private key
- `ulPrivateKeyAttributeCount`: Number of attributes in private key template
- `phPublicKey`: Pointer to variable to receive public key handle
- `phPrivateKey`: Pointer to variable to receive private key handle

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_MECHANISM_INVALID`: Invalid mechanism
- `CKR_MECHANISM_PARAM_INVALID`: Invalid mechanism parameters

#### C_WrapKey
Wraps (encrypts) a key.

```c
CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
               CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
               CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen);
```

Parameters:
- `hSession`: Handle of the session
- `pMechanism`: Pointer to mechanism structure
- `hWrappingKey`: Handle of wrapping key
- `hKey`: Handle of key to wrap
- `pWrappedKey`: Pointer to buffer to receive wrapped key (may be NULL)
- `pulWrappedKeyLen`: Pointer to variable containing buffer size/returned size

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_MECHANISM_INVALID`: Invalid mechanism
- `CKR_OBJECT_HANDLE_INVALID`: Invalid object handle

#### C_UnwrapKey
Unwraps (decrypts) a wrapped key.

```c
CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                 CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
                 CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
                 CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
```

Parameters:
- `hSession`: Handle of the session
- `pMechanism`: Pointer to mechanism structure
- `hUnwrappingKey`: Handle of unwrapping key
- `pWrappedKey`: Pointer to wrapped key
- `ulWrappedKeyLen`: Length of wrapped key
- `pTemplate`: Pointer to attribute template for unwrapped key
- `ulAttributeCount`: Number of attributes in template
- `phKey`: Pointer to variable to receive key handle

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_MECHANISM_INVALID`: Invalid mechanism
- `CKR_OBJECT_HANDLE_INVALID`: Invalid object handle

#### C_DeriveKey
Derives a key from a base key.

```c
CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                 CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
                 CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
```

Parameters:
- `hSession`: Handle of the session
- `pMechanism`: Pointer to mechanism structure
- `hBaseKey`: Handle of base key
- `pTemplate`: Pointer to attribute template for derived key
- `ulAttributeCount`: Number of attributes in template
- `phKey`: Pointer to variable to receive key handle

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_MECHANISM_INVALID`: Invalid mechanism
- `CKR_OBJECT_HANDLE_INVALID`: Invalid object handle

### Cryptographic Operations

#### C_EncryptInit
Initializes an encryption operation.

```c
CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                   CK_OBJECT_HANDLE hKey);
```

Parameters:
- `hSession`: Handle of the session
- `pMechanism`: Pointer to mechanism structure
- `hKey`: Handle of encryption key

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_MECHANISM_INVALID`: Invalid mechanism
- `CKR_OBJECT_HANDLE_INVALID`: Invalid object handle

#### C_Encrypt
Encrypts single-part data.

```c
CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
               CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen);
```

Parameters:
- `hSession`: Handle of the session
- `pData`: Pointer to data to encrypt
- `ulDataLen`: Length of data to encrypt
- `pEncryptedData`: Pointer to buffer to receive encrypted data (may be NULL)
- `pulEncryptedDataLen`: Pointer to variable containing buffer size/returned size

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_ARGUMENTS_BAD`: Invalid arguments

#### C_EncryptUpdate
Continues a multiple-part encryption operation.

```c
CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                     CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                     CK_ULONG_PTR pulEncryptedPartLen);
```

Parameters:
- `hSession`: Handle of the session
- `pPart`: Pointer to data part
- `ulPartLen`: Length of data part
- `pEncryptedPart`: Pointer to buffer to receive encrypted part (may be NULL)
- `pulEncryptedPartLen`: Pointer to variable containing buffer size/returned size

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_ARGUMENTS_BAD`: Invalid arguments

#### C_EncryptFinal
Finishes a multiple-part encryption operation.

```c
CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart,
                    CK_ULONG_PTR pulLastEncryptedPartLen);
```

Parameters:
- `hSession`: Handle of the session
- `pLastEncryptedPart`: Pointer to buffer to receive last encrypted part (may be NULL)
- `pulLastEncryptedPartLen`: Pointer to variable containing buffer size/returned size

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle

#### C_DecryptInit
Initializes a decryption operation.

```c
CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                   CK_OBJECT_HANDLE hKey);
```

Parameters:
- `hSession`: Handle of the session
- `pMechanism`: Pointer to mechanism structure
- `hKey`: Handle of decryption key

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_MECHANISM_INVALID`: Invalid mechanism
- `CKR_OBJECT_HANDLE_INVALID`: Invalid object handle

#### C_Decrypt
Decrypts encrypted data in a single part.

```c
CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData,
               CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
               CK_ULONG_PTR pulDataLen);
```

Parameters:
- `hSession`: Handle of the session
- `pEncryptedData`: Pointer to encrypted data
- `ulEncryptedDataLen`: Length of encrypted data
- `pData`: Pointer to buffer to receive decrypted data (may be NULL)
- `pulDataLen`: Pointer to variable containing buffer size/returned size

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_ARGUMENTS_BAD`: Invalid arguments

#### C_DecryptUpdate
Continues a multiple-part decryption operation.

```c
CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
                     CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
                     CK_ULONG_PTR pulPartLen);
```

Parameters:
- `hSession`: Handle of the session
- `pEncryptedPart`: Pointer to encrypted part
- `ulEncryptedPartLen`: Length of encrypted part
- `pPart`: Pointer to buffer to receive decrypted part (may be NULL)
- `pulPartLen`: Pointer to variable containing buffer size/returned size

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_ARGUMENTS_BAD`: Invalid arguments

#### C_DecryptFinal
Finishes a multiple-part decryption operation.

```c
CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart,
                    CK_ULONG_PTR pulLastPartLen);
```

Parameters:
- `hSession`: Handle of the session
- `pLastPart`: Pointer to buffer to receive last decrypted part (may be NULL)
- `pulLastPartLen`: Pointer to variable containing buffer size/returned size

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle

#### C_DigestInit
Initializes a message-digesting operation.

```c
CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism);
```

Parameters:
- `hSession`: Handle of the session
- `pMechanism`: Pointer to mechanism structure

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_MECHANISM_INVALID`: Invalid mechanism

#### C_Digest
Digests data in a single part.

```c
CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
              CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
```

Parameters:
- `hSession`: Handle of the session
- `pData`: Pointer to data to digest
- `ulDataLen`: Length of data to digest
- `pDigest`: Pointer to buffer to receive digest (may be NULL)
- `pulDigestLen`: Pointer to variable containing buffer size/returned size

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_ARGUMENTS_BAD`: Invalid arguments

#### C_DigestUpdate
Continues a multiple-part message-digesting operation.

```c
CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
```

Parameters:
- `hSession`: Handle of the session
- `pPart`: Pointer to data part
- `ulPartLen`: Length of data part

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_ARGUMENTS_BAD`: Invalid arguments

#### C_DigestKey
Continues a multi-part message-digesting operation, by digesting the value of a secret key.

```c
CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
```

Parameters:
- `hSession`: Handle of the session
- `hKey`: Handle of secret key to digest

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_OBJECT_HANDLE_INVALID`: Invalid object handle

#### C_DigestFinal
Finishes a multiple-part message-digesting operation.

```c
CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest,
                   CK_ULONG_PTR pulDigestLen);
```

Parameters:
- `hSession`: Handle of the session
- `pDigest`: Pointer to buffer to receive digest (may be NULL)
- `pulDigestLen`: Pointer to variable containing buffer size/returned size

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle

#### C_SignInit
Initializes a signature operation.

```c
CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                CK_OBJECT_HANDLE hKey);
```

Parameters:
- `hSession`: Handle of the session
- `pMechanism`: Pointer to mechanism structure
- `hKey`: Handle of signature key

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_MECHANISM_INVALID`: Invalid mechanism
- `CKR_OBJECT_HANDLE_INVALID`: Invalid object handle

#### C_Sign
Signs data in a single part.

```c
CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
            CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
```

Parameters:
- `hSession`: Handle of the session
- `pData`: Pointer to data to sign
- `ulDataLen`: Length of data to sign
- `pSignature`: Pointer to buffer to receive signature (may be NULL)
- `pulSignatureLen`: Pointer to variable containing buffer size/returned size

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_ARGUMENTS_BAD`: Invalid arguments

#### C_SignUpdate
Continues a multiple-part signature operation.

```c
CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
```

Parameters:
- `hSession`: Handle of the session
- `pPart`: Pointer to data part
- `ulPartLen`: Length of data part

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_ARGUMENTS_BAD`: Invalid arguments

#### C_SignFinal
Finishes a multiple-part signature operation.

```c
CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                 CK_ULONG_PTR pulSignatureLen);
```

Parameters:
- `hSession`: Handle of the session
- `pSignature`: Pointer to buffer to receive signature (may be NULL)
- `pulSignatureLen`: Pointer to variable containing buffer size/returned size

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle

#### C_SignRecoverInit
Initializes a signature operation, where the data can be recovered from the signature.

```c
CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                       CK_OBJECT_HANDLE hKey);
```

Parameters:
- `hSession`: Handle of the session
- `pMechanism`: Pointer to mechanism structure
- `hKey`: Handle of signature key

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_MECHANISM_INVALID`: Invalid mechanism
- `CKR_OBJECT_HANDLE_INVALID`: Invalid object handle

#### C_SignRecover
Signs data in a single part, where the data can be recovered from the signature.

```c
CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                   CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
```

Parameters:
- `hSession`: Handle of the session
- `pData`: Pointer to data to sign
- `ulDataLen`: Length of data to sign
- `pSignature`: Pointer to buffer to receive signature (may be NULL)
- `pulSignatureLen`: Pointer to variable containing buffer size/returned size

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_ARGUMENTS_BAD`: Invalid arguments

#### C_VerifyInit
Initializes a verification operation.

```c
CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                  CK_OBJECT_HANDLE hKey);
```

Parameters:
- `hSession`: Handle of the session
- `pMechanism`: Pointer to mechanism structure
- `hKey`: Handle of verification key

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_MECHANISM_INVALID`: Invalid mechanism
- `CKR_OBJECT_HANDLE_INVALID`: Invalid object handle

#### C_Verify
Verifies a signature in a single-part operation.

```c
CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
              CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
```

Parameters:
- `hSession`: Handle of the session
- `pData`: Pointer to data to verify
- `ulDataLen`: Length of data to verify
- `pSignature`: Pointer to signature
- `ulSignatureLen`: Length of signature

Returns:
- `CKR_OK`: Signature valid
- `CKR_SIGNATURE_INVALID`: Signature invalid
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_ARGUMENTS_BAD`: Invalid arguments

#### C_VerifyUpdate
Continues a multiple-part verification operation.

```c
CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
```

Parameters:
- `hSession`: Handle of the session
- `pPart`: Pointer to data part
- `ulPartLen`: Length of data part

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_ARGUMENTS_BAD`: Invalid arguments

#### C_VerifyFinal
Finishes a multiple-part verification operation.

```c
CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                   CK_ULONG ulSignatureLen);
```

Parameters:
- `hSession`: Handle of the session
- `pSignature`: Pointer to signature
- `ulSignatureLen`: Length of signature

Returns:
- `CKR_OK`: Signature valid
- `CKR_SIGNATURE_INVALID`: Signature invalid
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle

#### C_VerifyRecoverInit
Initializes a signature verification operation, where the data is recovered from the signature.

```c
CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                         CK_OBJECT_HANDLE hKey);
```

Parameters:
- `hSession`: Handle of the session
- `pMechanism`: Pointer to mechanism structure
- `hKey`: Handle of verification key

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_MECHANISM_INVALID`: Invalid mechanism
- `CKR_OBJECT_HANDLE_INVALID`: Invalid object handle

#### C_VerifyRecover
Verifies a signature in a single-part operation, where the data is recovered from the signature.

```c
CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                     CK_ULONG ulSignatureLen, CK_BYTE_PTR pData,
                     CK_ULONG_PTR pulDataLen);
```

Parameters:
- `hSession`: Handle of the session
- `pSignature`: Pointer to signature
- `ulSignatureLen`: Length of signature
- `pData`: Pointer to buffer to receive recovered data (may be NULL)
- `pulDataLen`: Pointer to variable containing buffer size/returned size

Returns:
- `CKR_OK`: Signature valid
- `CKR_SIGNATURE_INVALID`: Signature invalid
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_ARGUMENTS_BAD`: Invalid arguments

### Random Number Generation

#### C_GenerateRandom
Generates random or pseudo-random data.

```c
CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData,
                      CK_ULONG ulRandomLen);
```

Parameters:
- `hSession`: Handle of the session
- `pRandomData`: Pointer to buffer to receive random data
- `ulRandomLen`: Length of random data to generate

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_ARGUMENTS_BAD`: Invalid arguments

#### C_SeedRandom
Mixes additional seed material into the token's random number generator.

```c
CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen);
```

Parameters:
- `hSession`: Handle of the session
- `pSeed`: Pointer to seed material
- `ulSeedLen`: Length of seed material

Returns:
- `CKR_OK`: Success
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_ARGUMENTS_BAD`: Invalid arguments

## Error Codes

The following error codes are returned by PKCS#11 functions:

- `CKR_OK`: Success
- `CKR_CANCEL`: Operation cancelled
- `CKR_HOST_MEMORY`: Not enough memory available
- `CKR_SLOT_ID_INVALID`: Invalid slot ID
- `CKR_GENERAL_ERROR`: General error
- `CKR_FUNCTION_FAILED`: Function failed
- `CKR_ARGUMENTS_BAD`: Invalid arguments
- `CKR_NO_EVENT`: No event occurred
- `CKR_NEED_TO_CREATE_THREADS`: Need to create threads
- `CKR_CANT_LOCK`: Cannot lock data structures
- `CKR_ATTRIBUTE_READ_ONLY`: Attribute is read-only
- `CKR_ATTRIBUTE_SENSITIVE`: Attribute is sensitive
- `CKR_ATTRIBUTE_TYPE_INVALID`: Invalid attribute type
- `CKR_ATTRIBUTE_VALUE_INVALID`: Invalid attribute value
- `CKR_ACTION_PROHIBITED`: Action is prohibited
- `CKR_DATA_INVALID`: Data is invalid
- `CKR_DATA_LEN_RANGE`: Data length is out of range
- `CKR_DEVICE_ERROR`: Device error
- `CKR_DEVICE_MEMORY`: Not enough memory on device
- `CKR_DEVICE_REMOVED`: Device was removed
- `CKR_ENCRYPTED_DATA_INVALID`: Encrypted data is invalid
- `CKR_ENCRYPTED_DATA_LEN_RANGE`: Encrypted data length is out of range
- `CKR_FUNCTION_CANCELED`: Function was cancelled
- `CKR_FUNCTION_NOT_PARALLEL`: Function is not parallel
- `CKR_FUNCTION_NOT_SUPPORTED`: Function is not supported
- `CKR_KEY_HANDLE_INVALID`: Invalid key handle
- `CKR_KEY_SIZE_RANGE`: Key size is out of range
- `CKR_KEY_TYPE_INCONSISTENT`: Key type is inconsistent
- `CKR_KEY_NOT_NEEDED`: Key is not needed
- `CKR_KEY_CHANGED`: Key has changed
- `CKR_KEY_NEEDED`: Key is needed
- `CKR_KEY_INDIGESTIBLE`: Key is indigestible
- `CKR_KEY_FUNCTION_NOT_PERMITTED`: Key function is not permitted
- `CKR_KEY_NOT_WRAPPABLE`: Key is not wrappable
- `CKR_KEY_UNEXTRACTABLE`: Key is unextractable
- `CKR_MECHANISM_INVALID`: Invalid mechanism
- `CKR_MECHANISM_PARAM_INVALID`: Invalid mechanism parameters
- `CKR_OBJECT_HANDLE_INVALID`: Invalid object handle
- `CKR_OPERATION_ACTIVE`: Operation is already active
- `CKR_OPERATION_NOT_INITIALIZED`: Operation has not been initialized
- `CKR_PIN_INCORRECT`: PIN is incorrect
- `CKR_PIN_INVALID`: PIN is invalid
- `CKR_PIN_LEN_RANGE`: PIN length is out of range
- `CKR_PIN_EXPIRED`: PIN has expired
- `CKR_PIN_LOCKED`: PIN is locked
- `CKR_SESSION_CLOSED`: Session is closed
- `CKR_SESSION_COUNT`: Too many sessions open
- `CKR_SESSION_HANDLE_INVALID`: Invalid session handle
- `CKR_SESSION_PARALLEL_NOT_SUPPORTED`: Parallel sessions not supported
- `CKR_SESSION_READ_ONLY`: Session is read-only
- `CKR_SESSION_EXISTS`: Session already exists
- `CKR_SESSION_READ_ONLY_EXISTS`: Read-only session already exists
- `CKR_SESSION_READ_WRITE_SO_EXISTS`: Read/write SO session already exists
- `CKR_SIGNATURE_INVALID`: Signature is invalid
- `CKR_SIGNATURE_LEN_RANGE`: Signature length is out of range
- `CKR_TEMPLATE_INCOMPLETE`: Template is incomplete
- `CKR_TEMPLATE_INCONSISTENT`: Template is inconsistent
- `CKR_TOKEN_NOT_PRESENT`: Token is not present
- `CKR_TOKEN_NOT_RECOGNIZED`: Token is not recognized
- `CKR_TOKEN_WRITE_PROTECTED`: Token is write-protected
- `CKR_UNWRAPPING_KEY_HANDLE_INVALID`: Invalid unwrapping key handle
- `CKR_UNWRAPPING_KEY_SIZE_RANGE`: Unwrapping key size is out of range
- `CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT`: Unwrapping key type is inconsistent
- `CKR_USER_ALREADY_LOGGED_IN`: User is already logged in
- `CKR_USER_NOT_LOGGED_IN`: User is not logged in
- `CKR_USER_PIN_NOT_INITIALIZED`: User PIN is not initialized
- `CKR_USER_TYPE_INVALID`: Invalid user type
- `CKR_USER_ANOTHER_ALREADY_LOGGED_IN`: Another user is already logged in
- `CKR_USER_TOO_MANY_TYPES`: Too many user types
- `CKR_WRAPPED_KEY_INVALID`: Wrapped key is invalid
- `CKR_WRAPPED_KEY_LEN_RANGE`: Wrapped key length is out of range
- `CKR_WRAPPING_KEY_HANDLE_INVALID`: Invalid wrapping key handle
- `CKR_WRAPPING_KEY_SIZE_RANGE`: Wrapping key size is out of range
- `CKR_WRAPPING_KEY_TYPE_INCONSISTENT`: Wrapping key type is inconsistent
- `CKR_RANDOM_SEED_NOT_SUPPORTED`: Random seed is not supported
- `CKR_RANDOM_NO_RNG`: No random number generator available
- `CKR_DOMAIN_PARAMS_INVALID`: Domain parameters are invalid
- `CKR_CURVE_NOT_SUPPORTED`: Curve is not supported
- `CKR_BUFFER_TOO_SMALL`: Buffer is too small
- `CKR_SAVED_STATE_INVALID`: Saved state is invalid
- `CKR_INFORMATION_SENSITIVE`: Information is sensitive
- `CKR_STATE_UNSAVEABLE`: State cannot be saved
- `CKR_CRYPTOKI_NOT_INITIALIZED`: Cryptoki is not initialized
- `CKR_CRYPTOKI_ALREADY_INITIALIZED`: Cryptoki is already initialized
- `CKR_MUTEX_BAD`: Mutex is bad
- `CKR_MUTEX_NOT_LOCKED`: Mutex is not locked
- `CKR_NEW_PIN_MODE`: New PIN mode
- `CKR_NEXT_OTP`: Next OTP
- `CKR_EXCEEDED_MAX_ITERATIONS`: Exceeded maximum iterations
- `CKR_FIPS_SELF_TEST_FAILED`: FIPS self-test failed
- `CKR_LIBRARY_LOAD_FAILED`: Library load failed
- `CKR_PIN_TOO_WEAK`: PIN is too weak
- `CKR_PUBLIC_KEY_INVALID`: Public key is invalid
- `CKR_FUNCTION_REJECTED`: Function was rejected

## Constants

### Session Flags

- `CKF_RW_SESSION`: Read/write session
- `CKF_SERIAL_SESSION`: Serial session

### User Types

- `CKU_SO`: Security Officer
- `CKU_USER`: Normal user
- `CKU_CONTEXT_SPECIFIC`: Context specific

### Object Classes

- `CKO_DATA`: Data object
- `CKO_CERTIFICATE`: Certificate object
- `CKO_PUBLIC_KEY`: Public key object
- `CKO_PRIVATE_KEY`: Private key object
- `CKO_SECRET_KEY`: Secret key object
- `CKO_HW_FEATURE`: Hardware feature object
- `CKO_DOMAIN_PARAMETERS`: Domain parameters object
- `CKO_MECHANISM`: Mechanism object
- `CKO_OTP_KEY`: OTP key object

### Key Types

- `CKK_RSA`: RSA key
- `CKK_DSA`: DSA key
- `CKK_DH`: Diffie-Hellman key
- `CKK_ECDSA`: ECDSA key
- `CKK_EC`: Elliptic curve key
- `CKK_AES`: AES key
- `CKK_DES`: DES key
- `CKK_DES2`: Double DES key
- `CKK_DES3`: Triple DES key
- `CKK_CAST`: CAST key
- `CKK_CAST3`: CAST3 key
- `CKK_CAST128`: CAST128 key
- `CKK_RC2`: RC2 key
- `CKK_RC4`: RC4 key
- `CKK_RC5`: RC5 key
- `CKK_IDEA`: IDEA key
- `CKK_SKIPJACK`: Skipjack key
- `CKK_BATON`: Baton key
- `CKK_JUNIPER`: Juniper key
- `CKK_CDMF`: CDMF key
- `CKK_AES_XTS`: AES-XTS key
- `CKK_VENDOR_DEFINED`: Vendor-defined key

### Mechanisms

- `CKM_RSA_PKCS_KEY_PAIR_GEN`: RSA key pair generation
- `CKM_RSA_PKCS`: RSA PKCS#1 v1.5
- `CKM_RSA_9796`: RSA 9796
- `CKM_RSA_X_509`: RSA X.509
- `CKM_MD2_RSA_PKCS`: MD2 with RSA PKCS#1 v1.5
- `CKM_MD5_RSA_PKCS`: MD5 with RSA PKCS#1 v1.5
- `CKM_SHA1_RSA_PKCS`: SHA-1 with RSA PKCS#1 v1.5
- `CKM_RIPEMD128_RSA_PKCS`: RIPEMD-128 with RSA PKCS#1 v1.5
- `CKM_RIPEMD160_RSA_PKCS`: RIPEMD-160 with RSA PKCS#1 v1.5
- `CKM_RSA_PKCS_OAEP`: RSA PKCS#1 OAEP
- `CKM_RSA_X9_31_KEY_PAIR_GEN`: RSA X9.31 key pair generation
- `CKM_RSA_X9_31`: RSA X9.31
- `CKM_SHA1_RSA_X9_31`: SHA-1 with RSA X9.31
- `CKM_RSA_PKCS_PSS`: RSA PKCS#1 PSS
- `CKM_SHA1_RSA_PKCS_PSS`: SHA-1 with RSA PKCS#1 PSS
- `CKM_DSA_KEY_PAIR_GEN`: DSA key pair generation
- `CKM_DSA`: DSA
- `CKM_DSA_SHA1`: DSA with SHA-1
- `CKM_DSA_SHA224`: DSA with SHA-224
- `CKM_DSA_SHA256`: DSA with SHA-256
- `CKM_DSA_SHA384`: DSA with SHA-384
- `CKM_DSA_SHA512`: DSA with SHA-512
- `CKM_DH_PKCS_KEY_PAIR_GEN`: Diffie-Hellman key pair generation
- `CKM_DH_PKCS_DERIVE`: Diffie-Hellman key derivation
- `CKM_X9_42_DH_KEY_PAIR_GEN`: X9.42 Diffie-Hellman key pair generation
- `CKM_X9_42_DH_DERIVE`: X9.42 Diffie-Hellman key derivation
- `CKM_X9_42_DH_HYBRID_DERIVE`: X9.42 Diffie-Hellman hybrid key derivation
- `CKM_X9_42_MQV_DERIVE`: X9.42 MQV key derivation
- `CKM_SHA256_RSA_PKCS`: SHA-256 with RSA PKCS#1 v1.5
- `CKM_SHA384_RSA_PKCS`: SHA-384 with RSA PKCS#1 v1.5
- `CKM_SHA512_RSA_PKCS`: SHA-512 with RSA PKCS#1 v1.5
- `CKM_SHA256_RSA_PKCS_PSS`: SHA-256 with RSA PKCS#1 PSS
- `CKM_SHA384_RSA_PKCS_PSS`: SHA-384 with RSA PKCS#1 PSS
- `CKM_SHA512_RSA_PKCS_PSS`: SHA-512 with RSA PKCS#1 PSS
- `CKM_SHA224_RSA_PKCS`: SHA-224 with RSA PKCS#1 v1.5
- `CKM_SHA224_RSA_PKCS_PSS`: SHA-224 with RSA PKCS#1 PSS
- `CKM_RC2_KEY_GEN`: RC2 key generation
- `CKM_RC2_ECB`: RC2 ECB
- `CKM_RC2_CBC`: RC2 CBC
- `CKM_RC2_MAC`: RC2 MAC
- `CKM_RC2_MAC_GENERAL`: RC2 general MAC
- `CKM_RC2_CBC_PAD`: RC2 CBC with padding
- `CKM_RC4_KEY_GEN`: RC4 key generation
- `CKM_RC4`: RC4
- `CKM_DES_KEY_GEN`: DES key generation
- `CKM_DES_ECB`: DES ECB
- `CKM_DES_CBC`: DES CBC
- `CKM_DES_MAC`: DES MAC
- `CKM_DES_MAC_GENERAL`: DES general MAC
- `CKM_DES_CBC_PAD`: DES CBC with padding
- `CKM_DES2_KEY_GEN`: Double DES key generation
- `CKM_DES3_KEY_GEN`: Triple DES key generation
- `CKM_DES3_ECB`: Triple DES ECB
- `CKM_DES3_CBC`: Triple DES CBC
- `CKM_DES3_MAC`: Triple DES MAC
- `CKM_DES3_MAC_GENERAL`: Triple DES general MAC
- `CKM_DES3_CBC_PAD`: Triple DES CBC with padding
- `CKM_CDMF_KEY_GEN`: CDMF key generation
- `CKM_CDMF_ECB`: CDMF ECB
- `CKM_CDMF_CBC`: CDMF CBC
- `CKM_CDMF_MAC`: CDMF MAC
- `CKM_CDMF_MAC_GENERAL`: CDMF general MAC
- `CKM_CDMF_CBC_PAD`: CDMF CBC with padding
- `CKM_MD2`: MD2
- `CKM_MD2_HMAC`: MD2 HMAC
- `CKM_MD2_HMAC_GENERAL`: MD2 general HMAC
- `CKM_MD5`: MD5
- `CKM_MD5_HMAC`: MD5 HMAC
- `CKM_MD5_HMAC_GENERAL`: MD5 general HMAC
- `CKM_SHA_1`: SHA-1
- `CKM_SHA_1_HMAC`: SHA-1 HMAC
- `CKM_SHA_1_HMAC_GENERAL`: SHA-1 general HMAC
- `CKM_RIPEMD128`: RIPEMD-128
- `CKM_RIPEMD128_HMAC`: RIPEMD-128 HMAC
- `CKM_RIPEMD128_HMAC_GENERAL`: RIPEMD-128 general HMAC
- `CKM_RIPEMD160`: RIPEMD-160
- `CKM_RIPEMD160_HMAC`: RIPEMD-160 HMAC
- `CKM_RIPEMD160_HMAC_GENERAL`: RIPEMD-160 general HMAC
- `CKM_SHA256`: SHA-256
- `CKM_SHA256_HMAC`: SHA-256 HMAC
- `CKM_SHA256_HMAC_GENERAL`: SHA-256 general HMAC
- `CKM_SHA224`: SHA-224
- `CKM_SHA224_HMAC`: SHA-224 HMAC
- `CKM_SHA224_HMAC_GENERAL`: SHA-224 general HMAC
- `CKM_SHA384`: SHA-384
- `CKM_SHA384_HMAC`: SHA-384 HMAC
- `CKM_SHA384_HMAC_GENERAL`: SHA-384 general HMAC
- `CKM_SHA512`: SHA-512
- `CKM_SHA512_HMAC`: SHA-512 HMAC
- `CKM_SHA512_HMAC_GENERAL`: SHA-512 general HMAC
- `CKM_SECURID_KEY_GEN`: SecurID key generation
- `CKM_SECURID`: SecurID
- `CKM_HOTP_KEY_GEN`: HOTP key generation
- `CKM_HOTP`: HOTP
- `CKM_ACTI_KEY_GEN`: ACTI key generation
- `CKM_ACTI`: ACTI
- `CKM_CAST_KEY_GEN`: CAST key generation
- `CKM_CAST_ECB`: CAST ECB
- `CKM_CAST_CBC`: CAST CBC
- `CKM_CAST_MAC`: CAST MAC
- `CKM_CAST_MAC_GENERAL`: CAST general MAC
- `CKM_CAST_CBC_PAD`: CAST CBC with padding
- `CKM_CAST3_KEY_GEN`: CAST3 key generation
- `CKM_CAST3_ECB`: CAST3 ECB
- `CKM_CAST3_CBC`: CAST3 CBC
- `CKM_CAST3_MAC`: CAST3 MAC
- `CKM_CAST3_MAC_GENERAL`: CAST3 general MAC
- `CKM_CAST3_CBC_PAD`: CAST3 CBC with padding
- `CKM_CAST128_KEY_GEN`: CAST128 key generation
- `CKM_CAST128_ECB`: CAST128 ECB
- `CKM_CAST128_CBC`: CAST128 CBC
- `CKM_CAST128_MAC`: CAST128 MAC
- `CKM_CAST128_MAC_GENERAL`: CAST128 general MAC
- `CKM_CAST128_CBC_PAD`: CAST128 CBC with padding
- `CKM_RC5_KEY_GEN`: RC5 key generation
- `CKM_RC5_ECB`: RC5 ECB
- `CKM_RC5_CBC`: RC5 CBC
- `CKM_RC5_MAC`: RC5 MAC
- `CKM_RC5_MAC_GENERAL`: RC5 general MAC
- `CKM_RC5_CBC_PAD`: RC5 CBC with padding
- `CKM_IDEA_KEY_GEN`: IDEA key generation
- `CKM_IDEA_ECB`: IDEA ECB
- `CKM_IDEA_CBC`: IDEA CBC
- `CKM_IDEA_MAC`: IDEA MAC
- `CKM_IDEA_MAC_GENERAL`: IDEA general MAC
- `CKM_IDEA_CBC_PAD`: IDEA CBC with padding
- `CKM_GENERIC_SECRET_KEY_GEN`: Generic secret key generation
- `CKM_CONCATENATE_BASE_AND_KEY`: Concatenate base and key
- `CKM_CONCATENATE_BASE_AND_DATA`: Concatenate base and data
- `CKM_CONCATENATE_DATA_AND_BASE`: Concatenate data and base
- `CKM_XOR_BASE_AND_DATA`: XOR base and data
- `CKM_EXTRACT_KEY_FROM_KEY`: Extract key from key
- `CKM_SSL3_PRE_MASTER_KEY_GEN`: SSL3 pre-master key generation
- `CKM_SSL3_MASTER_KEY_DERIVE`: SSL3 master key derivation
- `CKM_SSL3_KEY_AND_MAC_DERIVE`: SSL3 key and MAC derivation
- `CKM_SSL3_MASTER_KEY_DERIVE_DH`: SSL3 master key derivation with DH
- `CKM_TLS_PRE_MASTER_KEY_GEN`: TLS pre-master key generation
- `CKM_TLS_MASTER_KEY_DERIVE`: TLS master key derivation
- `CKM_TLS_KEY_AND_MAC_DERIVE`: TLS key and MAC derivation
- `CKM_TLS_MASTER_KEY_DERIVE_DH`: TLS master key derivation with DH
- `CKM_TLS_PRF`: TLS PRF
- `CKM_SSL3_MD5_MAC`: SSL3 MD5 MAC
- `CKM_SSL3_SHA1_MAC`: SSL3 SHA-1 MAC
- `CKM_MD5_KEY_DERIVATION`: MD5 key derivation
- `CKM_MD2_KEY_DERIVATION`: MD2 key derivation
- `CKM_SHA1_KEY_DERIVATION`: SHA-1 key derivation
- `CKM_SHA256_KEY_DERIVATION`: SHA-256 key derivation
- `CKM_SHA384_KEY_DERIVATION`: SHA-384 key derivation
- `CKM_SHA512_KEY_DERIVATION`: SHA-512 key derivation
- `CKM_SHA224_KEY_DERIVATION`: SHA-224 key derivation
- `CKM_PBE_MD2_DES_CBC`: PBE MD2 DES CBC
- `CKM_PBE_MD5_DES_CBC`: PBE MD5 DES CBC
- `CKM_PBE_MD5_CAST_CBC`: PBE MD5 CAST CBC
- `CKM_PBE_MD5_CAST3_CBC`: PBE MD5 CAST3 CBC
- `CKM_PBE_MD5_CAST128_CBC`: PBE MD5 CAST128 CBC
- `CKM_PBE_SHA1_CAST128_CBC`: PBE SHA-1 CAST128 CBC
- `CKM_PBE_SHA1_RC4_128`: PBE SHA-1 RC4 128
- `CKM_PBE_SHA1_RC4_40`: PBE SHA-1 RC4 40
- `CKM_PBE_SHA1_DES3_EDE_CBC`: PBE SHA-1 Triple DES EDE CBC
- `CKM_PBE_SHA1_DES2_EDE_CBC`: PBE SHA-1 Double DES EDE CBC
- `CKM_PBE_SHA1_RC2_128_CBC`: PBE SHA-1 RC2 128 CBC
- `CKM_PBE_SHA1_RC2_40_CBC`: PBE SHA-1 RC2 40 CBC
- `CKM_PKCS5_PBKD2`: PKCS#5 PBKDF2
- `CKM_PBA_SHA1_WITH_SHA1_HMAC`: PBA SHA-1 with SHA-1 HMAC
- `CKM_WTLS_PRE_MASTER_KEY_GEN`: WTLS pre-master key generation
- `CKM_WTLS_MASTER_KEY_DERIVE`: WTLS master key derivation
- `CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC`: WTLS master key derivation with DH ECC
- `CKM_WTLS_PRF`: WTLS PRF
- `CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE`: WTLS server key and MAC derivation
- `CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE`: WTLS client key and MAC derivation
- `CKM_TLS10_MAC_SERVER`: TLS 1.0 MAC server
- `CKM_TLS10_MAC_CLIENT`: TLS 1.0 MAC client
- `CKM_TLS12_MAC`: TLS 1.2 MAC
- `CKM_TLS12_KDF`: TLS 1.2 KDF
- `CKM_TLS12_MASTER_KEY_DERIVE`: TLS 1.2 master key derivation
- `CKM_TLS12_KEY_AND_MAC_DERIVE`: TLS 1.2 key and MAC derivation
- `CKM_TLS12_MASTER_KEY_DERIVE_DH`: TLS 1.2 master key derivation with DH
- `CKM_TLS12_KEY_SAFE_DERIVE`: TLS 1.2 key safe derivation
- `CKM_TLS_MAC`: TLS MAC
- `CKM_TLS_KDF`: TLS KDF
- `CKM_KEY_WRAP_LYNKS`: Key wrap Lynks
- `CKM_KEY_WRAP_SET_OAEP`: Key wrap SET OAEP
- `CKM_CMS_SIG`: CMS signature
- `CKM_KIP_DERIVE`: KIP key derivation
- `CKM_KIP_WRAP`: KIP key wrap
- `CKM_KIP_MAC`: KIP MAC
- `CKM_CAMELLIA_KEY_GEN`: Camellia key generation
- `CKM_CAMELLIA_ECB`: Camellia ECB
- `CKM_CAMELLIA_CBC`: Camellia CBC
- `CKM_CAMELLIA_MAC`: Camellia MAC
- `CKM_CAMELLIA_MAC_GENERAL`: Camellia general MAC
- `CKM_CAMELLIA_CBC_PAD`: Camellia CBC with padding
- `CKM_CAMELLIA_ECB_ENCRYPT_DATA`: Camellia ECB encrypt data
- `CKM_CAMELLIA_CBC_ENCRYPT_DATA`: Camellia CBC encrypt data
- `CKM_CAMELLIA_CTR`: Camellia CTR
- `CKM_ARIA_KEY_GEN`: ARIA key generation
- `CKM_ARIA_ECB`: ARIA ECB
- `CKM_ARIA_CBC`: ARIA CBC
- `CKM_ARIA_MAC`: ARIA MAC
- `CKM_ARIA_MAC_GENERAL`: ARIA general MAC
- `CKM_ARIA_CBC_PAD`: ARIA CBC with padding
- `CKM_ARIA_ECB_ENCRYPT_DATA`: ARIA ECB encrypt data
- `CKM_ARIA_CBC_ENCRYPT_DATA`: ARIA CBC encrypt data
- `CKM_SEED_KEY_GEN`: SEED key generation
- `CKM_SEED_ECB`: SEED ECB
- `CKM_SEED_CBC`: SEED CBC
- `CKM_SEED_MAC`: SEED MAC
- `CKM_SEED_MAC_GENERAL`: SEED general MAC
- `CKM_SEED_CBC_PAD`: SEED CBC with padding
- `CKM_SEED_ECB_ENCRYPT_DATA`: SEED ECB encrypt data
- `CKM_SEED_CBC_ENCRYPT_DATA`: SEED CBC encrypt data
- `CKM_SKIPJACK_KEY_GEN`: Skipjack key generation
- `CKM_SKIPJACK_ECB64`: Skipjack ECB64
- `CKM_SKIPJACK_CBC64`: Skipjack CBC64
- `CKM_SKIPJACK_OFB64`: Skipjack OFB64
- `CKM_SKIPJACK_CFB64`: Skipjack CFB64
- `CKM_SKIPJACK_CFB32`: Skipjack CFB32
- `CKM_SKIPJACK_CFB16`: Skipjack CFB16
- `CKM_SKIPJACK_CFB8`: Skipjack CFB8
- `CKM_SKIPJACK_WRAP`: Skipjack wrap
- `CKM_SKIPJACK_PRIVATE_WRAP`: Skipjack private wrap
- `CKM_SKIPJACK_RELAYX`: Skipjack relayx
- `CKM_KEA_KEY_PAIR_GEN`: KEA key pair generation
- `CKM_KEA_KEY_DERIVE`: KEA key derivation
- `CKM_FORTEZZA_TIMESTAMP`: Fortezza timestamp
- `CKM_BATON_KEY_GEN`: Baton key generation
- `CKM_BATON_ECB128`: Baton ECB128
- `CKM_BATON_ECB96`: Baton ECB96
- `CKM_BATON_CBC128`: Baton CBC128
- `CKM_BATON_COUNTER`: Baton counter
- `CKM_BATON_SHUFFLE`: Baton shuffle
- `CKM_BATON_WRAP`: Baton wrap
- `CKM_ECDSA_KEY_PAIR_GEN`: ECDSA key pair generation
- `CKM_EC_KEY_PAIR_GEN`: EC key pair generation
- `CKM_ECDSA`: ECDSA
- `CKM_ECDSA_SHA1`: ECDSA with SHA-1
- `CKM_ECDSA_SHA224`: ECDSA with SHA-224
- `CKM_ECDSA_SHA256`: ECDSA with SHA-256
- `CKM_ECDSA_SHA384`: ECDSA with SHA-384
- `CKM_ECDSA_SHA512`: ECDSA with SHA-512
- `CKM_ECDH1_DERIVE`: ECDH key derivation
- `CKM_ECDH1_COFACTOR_DERIVE`: ECDH cofactor key derivation
- `CKM_ECMQV_DERIVE`: ECMQV key derivation
- `CKM_ECDH_AES_KEY_WRAP`: ECDH AES key wrap
- `CKM_RSA_AES_KEY_WRAP`: RSA AES key wrap
- `CKM_JUNIPER_KEY_GEN`: Juniper key generation
- `CKM_JUNIPER_ECB128`: Juniper ECB128
- `CKM_JUNIPER_CBC128`: Juniper CBC128
- `CKM_JUNIPER_COUNTER`: Juniper counter
- `CKM_JUNIPER_SHUFFLE`: Juniper shuffle
- `CKM_JUNIPER_WRAP`: Juniper wrap
- `CKM_FASTHASH`: Fast hash
- `CKM_AES_KEY_GEN`: AES key generation
- `CKM_AES_ECB`: AES ECB
- `CKM_AES_CBC`: AES CBC
- `CKM_AES_MAC`: AES MAC
- `CKM_AES_MAC_GENERAL`: AES general MAC
- `CKM_AES_CBC_PAD`: AES CBC with padding
- `CKM_AES_CTR`: AES CTR
- `CKM_AES_GCM`: AES GCM
- `CKM_AES_CCM`: AES CCM
- `CKM_AES_CTS`: AES CTS
- `CKM_AES_CMAC`: AES CMAC
- `CKM_AES_CMAC_GENERAL`: AES general CMAC
- `CKM_AES_XTS`: AES XTS
- `CKM_AES_XTS_KEY_GEN`: AES XTS key generation
- `CKM_AES_KEY_WRAP`: AES key wrap
- `CKM_AES_KEY_WRAP_PAD`: AES key wrap with padding
- `CKM_AES_GMAC`: AES GMAC
- `CKM_BLOWFISH_KEY_GEN`: Blowfish key generation
- `CKM_BLOWFISH_CBC`: Blowfish CBC
- `CKM_TWOFISH_KEY_GEN`: Twofish key generation
- `CKM_TWOFISH_CBC`: Twofish CBC
- `CKM_BLOWFISH_CBC_PAD`: Blowfish CBC with padding
- `CKM_TWOFISH_CBC_PAD`: Twofish CBC with padding
- `CKM_DES_ECB_ENCRYPT_DATA`: DES ECB encrypt data
- `CKM_DES_CBC_ENCRYPT_DATA`: DES CBC encrypt data
- `CKM_DES3_ECB_ENCRYPT_DATA`: Triple DES ECB encrypt data
- `CKM_DES3_CBC_ENCRYPT_DATA`: Triple DES CBC encrypt data
- `CKM_AES_ECB_ENCRYPT_DATA`: AES ECB encrypt data
- `CKM_AES_CBC_ENCRYPT_DATA`: AES CBC encrypt data
- `CKM_GOSTR3410_KEY_PAIR_GEN`: GOST R 34.10 key pair generation
- `CKM_GOSTR3410`: GOST R 34.10
- `CKM_GOSTR3410_WITH_GOSTR3411`: GOST R 34.10 with GOST R 34.11
- `CKM_GOSTR3410_KEY_WRAP`: GOST R 34.10 key wrap
- `CKM_GOSTR3410_DERIVE`: GOST R 34.10 key derivation
- `CKM_GOSTR3411`: GOST R 34.11
- `CKM_GOSTR3411_HMAC`: GOST R 34.11 HMAC
- `CKM_GOST28147_KEY_GEN`: GOST 28147 key generation
- `CKM_GOST28147_ECB`: GOST 28147 ECB
- `CKM_GOST28147`: GOST 28147
- `CKM_GOST28147_MAC`: GOST 28147 MAC
- `CKM_GOST28147_KEY_WRAP`: GOST 28147 key wrap
- `CKM_DSA_PARAMETER_GEN`: DSA parameter generation
- `CKM_DH_PKCS_PARAMETER_GEN`: Diffie-Hellman PKCS parameter generation
- `CKM_X9_42_DH_PARAMETER_GEN`: X9.42 Diffie-Hellman parameter generation
- `CKM_DSA_PROBABLISTIC_PARAMETER_GEN`: DSA probabilistic parameter generation
- `CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN`: DSA Shawe-Taylor parameter generation
- `CKM_AES_OFB`: AES OFB
- `CKM_AES_CFB64`: AES CFB64
- `CKM_AES_CFB8`: AES CFB8
- `CKM_AES_CFB128`: AES CFB128
- `CKM_AES_CFB1`: AES CFB1
- `CKM_VENDOR_DEFINED`: Vendor-defined mechanism

## Attributes

### Common Attributes

- `CKA_CLASS`: Object class
- `CKA_TOKEN`: Token object
- `CKA_PRIVATE`: Private object
- `CKA_LABEL`: Object label
- `CKA_APPLICATION`: Application that manages the object
- `CKA_VALUE`: Object value
- `CKA_OBJECT_ID`: Object identifier
- `CKA_CERTIFICATE_TYPE`: Certificate type
- `CKA_ISSUER`: Certificate issuer
- `CKA_SERIAL_NUMBER`: Certificate serial number
- `CKA_AC_ISSUER`: Attribute certificate issuer
- `CKA_OWNER`: Attribute certificate owner
- `CKA_ATTR_TYPES`: Attribute certificate attribute types
- `CKA_TRUSTED`: Trusted certificate
- `CKA_CERTIFICATE_CATEGORY`: Certificate category
- `CKA_JAVA_MIDP_SECURITY_DOMAIN`: Java MIDP security domain
- `CKA_URL`: URL where the complete certificate can be obtained
- `CKA_HASH_OF_SUBJECT_PUBLIC_KEY`: Hash of the subject public key
- `CKA_HASH_OF_ISSUER_PUBLIC_KEY`: Hash of the issuer public key
- `CKA_NAME_HASH_ALGORITHM`: Name hash algorithm
- `CKA_CHECK_VALUE`: Check value of the key
- `CKA_KEY_TYPE`: Key type
- `CKA_SUBJECT`: Certificate subject
- `CKA_ID`: Key identifier
- `CKA_SENSITIVE`: Sensitive key
- `CKA_ENCRYPT`: Key can be used for encryption
- `CKA_DECRYPT`: Key can be used for decryption
- `CKA_WRAP`: Key can be used for wrapping
- `CKA_UNWRAP`: Key can be used for unwrapping
- `CKA_SIGN`: Key can be used for signing
- `CKA_SIGN_RECOVER`: Key can be used for sign recovery
- `CKA_VERIFY`: Key can be used for verification
- `CKA_VERIFY_RECOVER`: Key can be used for verify recovery
- `CKA_DERIVE`: Key can be used for key derivation
- `CKA_START_DATE`: Start date for the key
- `CKA_END_DATE`: End date for the key
- `CKA_MODULUS`: RSA modulus
- `CKA_MODULUS_BITS`: RSA modulus bits
- `CKA_PUBLIC_EXPONENT`: RSA public exponent
- `CKA_PRIVATE_EXPONENT`: RSA private exponent
- `CKA_PRIME_1`: RSA prime 1
- `CKA_PRIME_2`: RSA prime 2
- `CKA_EXPONENT_1`: RSA exponent 1
- `CKA_EXPONENT_2`: RSA exponent 2
- `CKA_COEFFICIENT`: RSA coefficient
- `CKA_PUBLIC_KEY_INFO`: DER-encoding of the SubjectPublicKeyInfo
- `CKA_PRIME`: Prime number for Diffie-Hellman or DSA
- `CKA_SUBPRIME`: Subprime number for DSA
- `CKA_BASE`: Base number for Diffie-Hellman or DSA
- `CKA_PRIME_BITS`: Prime bits for Diffie-Hellman
- `CKA_SUBPRIME_BITS`: Subprime bits for DSA
- `CKA_VALUE_BITS`: Value bits
- `CKA_VALUE_LEN`: Value length
- `CKA_EXTRACTABLE`: Extractable key
- `CKA_LOCAL`: Local key
- `CKA_NEVER_EXTRACTABLE`: Never extractable key
- `CKA_ALWAYS_SENSITIVE`: Always sensitive key
- `CKA_KEY_GEN_MECHANISM`: Key generation mechanism
- `CKA_MODIFIABLE`: Modifiable object
- `CKA_COPYABLE`: Copyable object
- `CKA_DESTROYABLE`: Destroyable object
- `CKA_ECDSA_PARAMS`: ECDSA parameters
- `CKA_EC_PARAMS`: EC parameters
- `CKA_EC_POINT`: EC point
- `CKA_SECONDARY_AUTH`: Secondary authentication
- `CKA_AUTH_PIN_FLAGS`: Authentication PIN flags
- `CKA_ALWAYS_AUTHENTICATE`: Always authenticate
- `CKA_WRAP_WITH_TRUSTED`: Wrap with trusted key
- `CKA_WRAP_TEMPLATE`: Wrap template
- `CKA_UNWRAP_TEMPLATE`: Unwrap template
- `CKA_DERIVE_TEMPLATE`: Derive template
- `CKA_OTP_FORMAT`: OTP format
- `CKA_OTP_LENGTH`: OTP length
- `CKA_OTP_TIME_INTERVAL`: OTP time interval
- `CKA_OTP_USER_FRIENDLY_MODE`: OTP user friendly mode
- `CKA_OTP_CHALLENGE_REQUIREMENT`: OTP challenge requirement
- `CKA_OTP_TIME_REQUIREMENT`: OTP time requirement
- `CKA_OTP_COUNTER_REQUIREMENT`: OTP counter requirement
- `CKA_OTP_PIN_REQUIREMENT`: OTP PIN requirement
- `CKA_OTP_COUNTER`: OTP counter
- `CKA_OTP_TIME`: OTP time
- `CKA_OTP_USER_IDENTIFIER`: OTP user identifier
- `CKA_OTP_SERVICE_IDENTIFIER`: OTP service identifier
- `CKA_OTP_SERVICE_LOGO`: OTP service logo
- `CKA_OTP_SERVICE_LOGO_TYPE`: OTP service logo type
- `CKA_GOSTR3410_PARAMS`: GOST R 34.10 parameters
- `CKA_GOSTR3411_PARAMS`: GOST R 34.11 parameters
- `CKA_GOST28147_PARAMS`: GOST 28147 parameters
- `CKA_HW_FEATURE_TYPE`: Hardware feature type
- `CKA_RESET_ON_INIT`: Reset on initialization
- `CKA_HAS_RESET`: Has been reset
- `CKA_PIXEL_X`: Pixel X
- `CKA_PIXEL_Y`: Pixel Y
- `CKA_RESOLUTION`: Resolution
- `CKA_CHAR_ROWS`: Character rows
- `CKA_CHAR_COLUMNS`: Character columns
- `CKA_COLOR`: Color
- `CKA_BITS_PER_PIXEL`: Bits per pixel
- `CKA_CHAR_SETS`: Character sets
- `CKA_ENCODING_METHODS`: Encoding methods
- `CKA_MIME_TYPES`: MIME types
- `CKA_MECHANISM_TYPE`: Mechanism type
- `CKA_REQUIRED_CMS_ATTRIBUTES`: Required CMS attributes
- `CKA_DEFAULT_CMS_ATTRIBUTES`: Default CMS attributes
- `CKA_SUPPORTED_CMS_ATTRIBUTES`: Supported CMS attributes
- `CKA_ALLOWED_MECHANISMS`: Allowed mechanisms
- `CKA_VENDOR_DEFINED`: Vendor-defined attribute