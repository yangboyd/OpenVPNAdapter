//
//  KeychainError.swift
//  OpenVPN Adapter
//
//  Created by Sergey Abramchuk on 01.09.17.
//
//

import Foundation
import Security

enum KeychainError: Error {
    case unimplemented
    case diskFull
    case io
    case opWr
    case param
    case wrPerm
    case allocate
    case userCanceled
    case badReq
    case internalComponent
    case coreFoundationUnknown
    case missingEntitlement
    case notAvailable
    case readOnly
    case authFailed
    case noSuchKeychain
    case invalidKeychain
    case duplicateKeychain
    case duplicateCallback
    case invalidCallback
    case duplicateItem
    case itemNotFound
    case bufferTooSmall
    case dataTooLarge
    case noSuchAttr
    case invalidItemRef
    case invalidSearchRef
    case noSuchClass
    case noDefaultKeychain
    case interactionNotAllowed
    case readOnlyAttr
    case wrongSecVersion
    case keySizeNotAllowed
    case noStorageModule
    case noCertificateModule
    case noPolicyModule
    case interactionRequired
    case dataNotAvailable
    case dataNotModifiable
    case createChainFailed
    case invalidPrefsDomain
    case inDarkWake
    case aclNotSimple
    case policyNotFound
    case invalidTrustSetting
    case noAccessForItem
    case invalidOwnerEdit
    case trustNotAvailable
    case unsupportedFormat
    case unknownFormat
    case keyIsSensitive
    case multiplePrivKeys
    case passphraseRequired
    case invalidPasswordRef
    case invalidTrustSettings
    case noTrustSettings
    case pkcs12VerifyFailure
    case notSigner
    case decode
    case serviceNotAvailable
    case insufficientClientID
    case deviceReset
    case deviceFailed
    case appleAddAppACLSubject
    case applePublicKeyIncomplete
    case appleSignatureMismatch
    case appleInvalidKeyStartDate
    case appleInvalidKeyEndDate
    case conversionError
    case appleSSLv2Rollback
    case quotaExceeded
    case fileTooBig
    case invalidDatabaseBlob
    case invalidKeyBlob
    case incompatibleDatabaseBlob
    case incompatibleKeyBlob
    case hostNameMismatch
    case unknownCriticalExtensionFlag
    case noBasicConstraints
    case noBasicConstraintsCA
    case invalidAuthorityKeyID
    case invalidSubjectKeyID
    case invalidKeyUsageForPolicy
    case invalidExtendedKeyUsage
    case invalidIDLinkage
    case pathLengthConstraintExceeded
    case invalidRoot
    case crlExpired
    case crlNotValidYet
    case crlNotFound
    case crlServerDown
    case crlBadURI
    case unknownCertExtension
    case unknownCRLExtension
    case crlNotTrusted
    case crlPolicyFailed
    case idPFailure
    case smimeEmailAddressesNotFound
    case smimeBadExtendedKeyUsage
    case smimeBadKeyUsage
    case smimeKeyUsageNotCritical
    case smimeNoEmailAddress
    case smimeSubjAltNameNotCritical
    case sslBadExtendedKeyUsage
    case ocspBadResponse
    case ocspBadRequest
    case ocspUnavailable
    case ocspStatusUnrecognized
    case endOfData
    case incompleteCertRevocationCheck
    case networkFailure
    case ocspNotTrustedToAnchor
    case recordModified
    case ocspSignatureError
    case ocspNoSigner
    case ocspResponderMalformedReq
    case ocspResponderInternalError
    case ocspResponderTryLater
    case ocspResponderSignatureRequired
    case ocspResponderUnauthorized
    case ocspResponseNonceMismatch
    case codeSigningBadCertChainLength
    case codeSigningNoBasicConstraints
    case codeSigningBadPathLengthConstraint
    case codeSigningNoExtendedKeyUsage
    case codeSigningDevelopment
    case resourceSignBadCertChainLength
    case resourceSignBadExtKeyUsage
    case trustSettingDeny
    case invalidSubjectName
    case unknownQualifiedCertStatement
    case mobileMeRequestQueued
    case mobileMeRequestRedirected
    case mobileMeServerError
    case mobileMeServerNotAvailable
    case mobileMeServerAlreadyExists
    case mobileMeServerServiceErr
    case mobileMeRequestAlreadyPending
    case mobileMeNoRequestPending
    case mobileMeCSRVerifyFailure
    case mobileMeFailedConsistencyCheck
    case notInitialized
    case invalidHandleUsage
    case pvcReferentNotFound
    case functionIntegrityFail
    case internalError
    case memoryError
    case invalidData
    case mdsError
    case invalidPointer
    case selfCheckFailed
    case functionFailed
    case moduleManifestVerifyFailed
    case invalidGUID
    case invalidHandle
    case invalidDBList
    case invalidPassthroughID
    case invalidNetworkAddress
    case crlAlreadySigned
    case invalidNumberOfFields
    case verificationFailure
    case unknownTag
    case invalidSignature
    case invalidName
    case invalidCertificateRef
    case invalidCertificateGroup
    case tagNotFound
    case invalidQuery
    case invalidValue
    case callbackFailed
    case aclDeleteFailed
    case aclReplaceFailed
    case aclAddFailed
    case aclChangeFailed
    case invalidAccessCredentials
    case invalidRecord
    case invalidACL
    case invalidSampleValue
    case incompatibleVersion
    case privilegeNotGranted
    case invalidScope
    case pvcAlreadyConfigured
    case invalidPVC
    case emmLoadFailed
    case emmUnloadFailed
    case addinLoadFailed
    case invalidKeyRef
    case invalidKeyHierarchy
    case addinUnloadFailed
    case libraryReferenceNotFound
    case invalidAddinFunctionTable
    case invalidServiceMask
    case moduleNotLoaded
    case invalidSubServiceID
    case attributeNotInContext
    case moduleManagerInitializeFailed
    case moduleManagerNotFound
    case eventNotificationCallbackNotFound
    case inputLengthError
    case outputLengthError
    case privilegeNotSupported
    case deviceError
    case attachHandleBusy
    case notLoggedIn
    case algorithmMismatch
    case keyUsageIncorrect
    case keyBlobTypeIncorrect
    case keyHeaderInconsistent
    case unsupportedKeyFormat
    case unsupportedKeySize
    case invalidKeyUsageMask
    case unsupportedKeyUsageMask
    case invalidKeyAttributeMask
    case unsupportedKeyAttributeMask
    case invalidKeyLabel
    case unsupportedKeyLabel
    case invalidKeyFormat
    case unsupportedVectorOfBuffers
    case invalidInputVector
    case invalidOutputVector
    case invalidContext
    case invalidAlgorithm
    case invalidAttributeKey
    case missingAttributeKey
    case invalidAttributeInitVector
    case missingAttributeInitVector
    case invalidAttributeSalt
    case missingAttributeSalt
    case invalidAttributePadding
    case missingAttributePadding
    case invalidAttributeRandom
    case missingAttributeRandom
    case invalidAttributeSeed
    case missingAttributeSeed
    case invalidAttributePassphrase
    case missingAttributePassphrase
    case invalidAttributeKeyLength
    case missingAttributeKeyLength
    case invalidAttributeBlockSize
    case missingAttributeBlockSize
    case invalidAttributeOutputSize
    case missingAttributeOutputSize
    case invalidAttributeRounds
    case missingAttributeRounds
    case invalidAlgorithmParms
    case missingAlgorithmParms
    case invalidAttributeLabel
    case missingAttributeLabel
    case invalidAttributeKeyType
    case missingAttributeKeyType
    case invalidAttributeMode
    case missingAttributeMode
    case invalidAttributeEffectiveBits
    case missingAttributeEffectiveBits
    case invalidAttributeStartDate
    case missingAttributeStartDate
    case invalidAttributeEndDate
    case missingAttributeEndDate
    case invalidAttributeVersion
    case missingAttributeVersion
    case invalidAttributePrime
    case missingAttributePrime
    case invalidAttributeBase
    case missingAttributeBase
    case invalidAttributeSubprime
    case missingAttributeSubprime
    case invalidAttributeIterationCount
    case missingAttributeIterationCount
    case invalidAttributeDLDBHandle
    case missingAttributeDLDBHandle
    case invalidAttributeAccessCredentials
    case missingAttributeAccessCredentials
    case invalidAttributePublicKeyFormat
    case missingAttributePublicKeyFormat
    case invalidAttributePrivateKeyFormat
    case missingAttributePrivateKeyFormat
    case invalidAttributeSymmetricKeyFormat
    case missingAttributeSymmetricKeyFormat
    case invalidAttributeWrappedKeyFormat
    case missingAttributeWrappedKeyFormat
    case stagedOperationInProgress
    case stagedOperationNotStarted
    case verifyFailed
    case querySizeUnknown
    case blockSizeMismatch
    case publicKeyInconsistent
    case deviceVerifyFailed
    case invalidLoginName
    case alreadyLoggedIn
    case invalidDigestAlgorithm
    case invalidCRLGroup
    case certificateCannotOperate
    case certificateExpired
    case certificateNotValidYet
    case certificateRevoked
    case certificateSuspended
    case insufficientCredentials
    case invalidAction
    case invalidAuthority
    case verifyActionFailed
    case invalidCertAuthority
    case invaldCRLAuthority
    case invalidCRLEncoding
    case invalidCRLType
    case invalidCRL
    case invalidFormType
    case invalidID
    case invalidIdentifier
    case invalidIndex
    case invalidPolicyIdentifiers
    case invalidTimeString
    case invalidReason
    case invalidRequestInputs
    case invalidResponseVector
    case invalidStopOnPolicy
    case invalidTuple
    case multipleValuesUnsupported
    case notTrusted
    case noDefaultAuthority
    case rejectedForm
    case requestLost
    case requestRejected
    case unsupportedAddressType
    case unsupportedService
    case invalidTupleGroup
    case invalidBaseACLs
    case invalidTupleCredendtials
    case invalidEncoding
    case invalidValidityPeriod
    case invalidRequestor
    case requestDescriptor
    case invalidBundleInfo
    case invalidCRLIndex
    case noFieldValues
    case unsupportedFieldFormat
    case unsupportedIndexInfo
    case unsupportedLocality
    case unsupportedNumAttributes
    case unsupportedNumIndexes
    case unsupportedNumRecordTypes
    case fieldSpecifiedMultiple
    case incompatibleFieldFormat
    case invalidParsingModule
    case databaseLocked
    case datastoreIsOpen
    case missingValue
    case unsupportedQueryLimits
    case unsupportedNumSelectionPreds
    case unsupportedOperator
    case invalidDBLocation
    case invalidAccessRequest
    case invalidIndexInfo
    case invalidNewOwner
    case invalidModifyMode
    case missingRequiredExtension
    case extendedKeyUsageNotCritical
    case timestampMissing
    case timestampInvalid
    case timestampNotTrusted
    case timestampServiceNotAvailable
    case timestampBadAlg
    case timestampBadRequest
    case timestampBadDataFormat
    case timestampTimeNotAvailable
    case timestampUnacceptedPolicy
    case timestampUnacceptedExtension
    case timestampAddInfoNotAvailable
    case timestampSystemFailure
    case signingTimeMissing
    case timestampRejection
    case timestampWaiting
    case timestampRevocationWarning
    case timestampRevocationNotification
    case unexpected
}

extension KeychainError: RawRepresentable {

    init?(rawValue: OSStatus) {
        switch rawValue {
        case errSecUnimplemented: self = .unimplemented
        case errSecDskFull: self = .diskFull
        case errSecDiskFull: self = .diskFull
        case errSecIO: self = .io
        case errSecOpWr: self = .opWr
        case errSecParam: self = .param
        case errSecWrPerm: self = .wrPerm
        case errSecAllocate: self = .allocate
        case errSecUserCanceled: self = .userCanceled
        case errSecBadReq: self = .badReq
        case errSecInternalComponent: self = .internalComponent
        case errSecCoreFoundationUnknown: self = .coreFoundationUnknown
        case errSecMissingEntitlement: self = .missingEntitlement
        case errSecNotAvailable: self = .notAvailable
        case errSecReadOnly: self = .readOnly
        case errSecAuthFailed: self = .authFailed
        case errSecNoSuchKeychain: self = .noSuchKeychain
        case errSecInvalidKeychain: self = .invalidKeychain
        case errSecDuplicateKeychain: self = .duplicateKeychain
        case errSecDuplicateCallback: self = .duplicateCallback
        case errSecInvalidCallback: self = .invalidCallback
        case errSecDuplicateItem: self = .duplicateItem
        case errSecItemNotFound: self = .itemNotFound
        case errSecBufferTooSmall: self = .bufferTooSmall
        case errSecDataTooLarge: self = .dataTooLarge
        case errSecNoSuchAttr: self = .noSuchAttr
        case errSecInvalidItemRef: self = .invalidItemRef
        case errSecInvalidSearchRef: self = .invalidSearchRef
        case errSecNoSuchClass: self = .noSuchClass
        case errSecNoDefaultKeychain: self = .noDefaultKeychain
        case errSecInteractionNotAllowed: self = .interactionNotAllowed
        case errSecReadOnlyAttr: self = .readOnlyAttr
        case errSecWrongSecVersion: self = .wrongSecVersion
        case errSecKeySizeNotAllowed: self = .keySizeNotAllowed
        case errSecNoStorageModule: self = .noStorageModule
        case errSecNoCertificateModule: self = .noCertificateModule
        case errSecNoPolicyModule: self = .noPolicyModule
        case errSecInteractionRequired: self = .interactionRequired
        case errSecDataNotAvailable: self = .dataNotAvailable
        case errSecDataNotModifiable: self = .dataNotModifiable
        case errSecCreateChainFailed: self = .createChainFailed
        case errSecInvalidPrefsDomain: self = .invalidPrefsDomain
        case errSecInDarkWake: self = .inDarkWake
        case errSecACLNotSimple: self = .aclNotSimple
        case errSecPolicyNotFound: self = .policyNotFound
        case errSecInvalidTrustSetting: self = .invalidTrustSetting
        case errSecNoAccessForItem: self = .noAccessForItem
        case errSecInvalidOwnerEdit: self = .invalidOwnerEdit
        case errSecTrustNotAvailable: self = .trustNotAvailable
        case errSecUnsupportedFormat: self = .unsupportedFormat
        case errSecUnknownFormat: self = .unknownFormat
        case errSecKeyIsSensitive: self = .keyIsSensitive
        case errSecMultiplePrivKeys: self = .multiplePrivKeys
        case errSecPassphraseRequired: self = .passphraseRequired
        case errSecInvalidPasswordRef: self = .invalidPasswordRef
        case errSecInvalidTrustSettings: self = .invalidTrustSettings
        case errSecNoTrustSettings: self = .noTrustSettings
        case errSecPkcs12VerifyFailure: self = .pkcs12VerifyFailure
        case errSecNotSigner: self = .notSigner
        case errSecDecode: self = .decode
        case errSecServiceNotAvailable: self = .serviceNotAvailable
        case errSecInsufficientClientID: self = .insufficientClientID
        case errSecDeviceReset: self = .deviceReset
        case errSecDeviceFailed: self = .deviceFailed
        case errSecAppleAddAppACLSubject: self = .appleAddAppACLSubject
        case errSecApplePublicKeyIncomplete: self = .applePublicKeyIncomplete
        case errSecAppleSignatureMismatch: self = .appleSignatureMismatch
        case errSecAppleInvalidKeyStartDate: self = .appleInvalidKeyStartDate
        case errSecAppleInvalidKeyEndDate: self = .appleInvalidKeyEndDate
        case errSecConversionError: self = .conversionError
        case errSecAppleSSLv2Rollback: self = .appleSSLv2Rollback
        case errSecQuotaExceeded: self = .quotaExceeded
        case errSecFileTooBig: self = .fileTooBig
        case errSecInvalidDatabaseBlob: self = .invalidDatabaseBlob
        case errSecInvalidKeyBlob: self = .invalidKeyBlob
        case errSecIncompatibleDatabaseBlob: self = .incompatibleDatabaseBlob
        case errSecIncompatibleKeyBlob: self = .incompatibleKeyBlob
        case errSecHostNameMismatch: self = .hostNameMismatch
        case errSecUnknownCriticalExtensionFlag: self = .unknownCriticalExtensionFlag
        case errSecNoBasicConstraints: self = .noBasicConstraints
        case errSecNoBasicConstraintsCA: self = .noBasicConstraintsCA
        case errSecInvalidAuthorityKeyID: self = .invalidAuthorityKeyID
        case errSecInvalidSubjectKeyID: self = .invalidSubjectKeyID
        case errSecInvalidKeyUsageForPolicy: self = .invalidKeyUsageForPolicy
        case errSecInvalidExtendedKeyUsage: self = .invalidExtendedKeyUsage
        case errSecInvalidIDLinkage: self = .invalidIDLinkage
        case errSecPathLengthConstraintExceeded: self = .pathLengthConstraintExceeded
        case errSecInvalidRoot: self = .invalidRoot
        case errSecCRLExpired: self = .crlExpired
        case errSecCRLNotValidYet: self = .crlNotValidYet
        case errSecCRLNotFound: self = .crlNotFound
        case errSecCRLServerDown: self = .crlServerDown
        case errSecCRLBadURI: self = .crlBadURI
        case errSecUnknownCertExtension: self = .unknownCertExtension
        case errSecUnknownCRLExtension: self = .unknownCRLExtension
        case errSecCRLNotTrusted: self = .crlNotTrusted
        case errSecCRLPolicyFailed: self = .crlPolicyFailed
        case errSecIDPFailure: self = .idPFailure
        case errSecSMIMEEmailAddressesNotFound: self = .smimeEmailAddressesNotFound
        case errSecSMIMEBadExtendedKeyUsage: self = .smimeBadExtendedKeyUsage
        case errSecSMIMEBadKeyUsage: self = .smimeBadKeyUsage
        case errSecSMIMEKeyUsageNotCritical: self = .smimeKeyUsageNotCritical
        case errSecSMIMENoEmailAddress: self = .smimeNoEmailAddress
        case errSecSMIMESubjAltNameNotCritical: self = .smimeSubjAltNameNotCritical
        case errSecSSLBadExtendedKeyUsage: self = .sslBadExtendedKeyUsage
        case errSecOCSPBadResponse: self = .ocspBadResponse
        case errSecOCSPBadRequest: self = .ocspBadRequest
        case errSecOCSPUnavailable: self = .ocspUnavailable
        case errSecOCSPStatusUnrecognized: self = .ocspStatusUnrecognized
        case errSecEndOfData: self = .endOfData
        case errSecIncompleteCertRevocationCheck: self = .incompleteCertRevocationCheck
        case errSecNetworkFailure: self = .networkFailure
        case errSecOCSPNotTrustedToAnchor: self = .ocspNotTrustedToAnchor
        case errSecRecordModified: self = .recordModified
        case errSecOCSPSignatureError: self = .ocspSignatureError
        case errSecOCSPNoSigner: self = .ocspNoSigner
        case errSecOCSPResponderMalformedReq: self = .ocspResponderMalformedReq
        case errSecOCSPResponderInternalError: self = .ocspResponderInternalError
        case errSecOCSPResponderTryLater: self = .ocspResponderTryLater
        case errSecOCSPResponderSignatureRequired: self = .ocspResponderSignatureRequired
        case errSecOCSPResponderUnauthorized: self = .ocspResponderUnauthorized
        case errSecOCSPResponseNonceMismatch: self = .ocspResponseNonceMismatch
        case errSecCodeSigningBadCertChainLength: self = .codeSigningBadCertChainLength
        case errSecCodeSigningNoBasicConstraints: self = .codeSigningNoBasicConstraints
        case errSecCodeSigningBadPathLengthConstraint: self = .codeSigningBadPathLengthConstraint
        case errSecCodeSigningNoExtendedKeyUsage: self = .codeSigningNoExtendedKeyUsage
        case errSecCodeSigningDevelopment: self = .codeSigningDevelopment
        case errSecResourceSignBadCertChainLength: self = .resourceSignBadCertChainLength
        case errSecResourceSignBadExtKeyUsage: self = .resourceSignBadExtKeyUsage
        case errSecTrustSettingDeny: self = .trustSettingDeny
        case errSecInvalidSubjectName: self = .invalidSubjectName
        case errSecUnknownQualifiedCertStatement: self = .unknownQualifiedCertStatement
        case errSecMobileMeRequestQueued: self = .mobileMeRequestQueued
        case errSecMobileMeRequestRedirected: self = .mobileMeRequestRedirected
        case errSecMobileMeServerError: self = .mobileMeServerError
        case errSecMobileMeServerNotAvailable: self = .mobileMeServerNotAvailable
        case errSecMobileMeServerAlreadyExists: self = .mobileMeServerAlreadyExists
        case errSecMobileMeServerServiceErr: self = .mobileMeServerServiceErr
        case errSecMobileMeRequestAlreadyPending: self = .mobileMeRequestAlreadyPending
        case errSecMobileMeNoRequestPending: self = .mobileMeNoRequestPending
        case errSecMobileMeCSRVerifyFailure: self = .mobileMeCSRVerifyFailure
        case errSecMobileMeFailedConsistencyCheck: self = .mobileMeFailedConsistencyCheck
        case errSecNotInitialized: self = .notInitialized
        case errSecInvalidHandleUsage: self = .invalidHandleUsage
        case errSecPVCReferentNotFound: self = .pvcReferentNotFound
        case errSecFunctionIntegrityFail: self = .functionIntegrityFail
        case errSecInternalError: self = .internalError
        case errSecMemoryError: self = .memoryError
        case errSecInvalidData: self = .invalidData
        case errSecMDSError: self = .mdsError
        case errSecInvalidPointer: self = .invalidPointer
        case errSecSelfCheckFailed: self = .selfCheckFailed
        case errSecFunctionFailed: self = .functionFailed
        case errSecModuleManifestVerifyFailed: self = .moduleManifestVerifyFailed
        case errSecInvalidGUID: self = .invalidGUID
        case errSecInvalidHandle: self = .invalidHandle
        case errSecInvalidDBList: self = .invalidDBList
        case errSecInvalidPassthroughID: self = .invalidPassthroughID
        case errSecInvalidNetworkAddress: self = .invalidNetworkAddress
        case errSecCRLAlreadySigned: self = .crlAlreadySigned
        case errSecInvalidNumberOfFields: self = .invalidNumberOfFields
        case errSecVerificationFailure: self = .verificationFailure
        case errSecUnknownTag: self = .unknownTag
        case errSecInvalidSignature: self = .invalidSignature
        case errSecInvalidName: self = .invalidName
        case errSecInvalidCertificateRef: self = .invalidCertificateRef
        case errSecInvalidCertificateGroup: self = .invalidCertificateGroup
        case errSecTagNotFound: self = .tagNotFound
        case errSecInvalidQuery: self = .invalidQuery
        case errSecInvalidValue: self = .invalidValue
        case errSecCallbackFailed: self = .callbackFailed
        case errSecACLDeleteFailed: self = .aclDeleteFailed
        case errSecACLReplaceFailed: self = .aclReplaceFailed
        case errSecACLAddFailed: self = .aclAddFailed
        case errSecACLChangeFailed: self = .aclChangeFailed
        case errSecInvalidAccessCredentials: self = .invalidAccessCredentials
        case errSecInvalidRecord: self = .invalidRecord
        case errSecInvalidACL: self = .invalidACL
        case errSecInvalidSampleValue: self = .invalidSampleValue
        case errSecIncompatibleVersion: self = .incompatibleVersion
        case errSecPrivilegeNotGranted: self = .privilegeNotGranted
        case errSecInvalidScope: self = .invalidScope
        case errSecPVCAlreadyConfigured: self = .pvcAlreadyConfigured
        case errSecInvalidPVC: self = .invalidPVC
        case errSecEMMLoadFailed: self = .emmLoadFailed
        case errSecEMMUnloadFailed: self = .emmUnloadFailed
        case errSecAddinLoadFailed: self = .addinLoadFailed
        case errSecInvalidKeyRef: self = .invalidKeyRef
        case errSecInvalidKeyHierarchy: self = .invalidKeyHierarchy
        case errSecAddinUnloadFailed: self = .addinUnloadFailed
        case errSecLibraryReferenceNotFound: self = .libraryReferenceNotFound
        case errSecInvalidAddinFunctionTable: self = .invalidAddinFunctionTable
        case errSecInvalidServiceMask: self = .invalidServiceMask
        case errSecModuleNotLoaded: self = .moduleNotLoaded
        case errSecInvalidSubServiceID: self = .invalidSubServiceID
        case errSecAttributeNotInContext: self = .attributeNotInContext
        case errSecModuleManagerInitializeFailed: self = .moduleManagerInitializeFailed
        case errSecModuleManagerNotFound: self = .moduleManagerNotFound
        case errSecEventNotificationCallbackNotFound: self = .eventNotificationCallbackNotFound
        case errSecInputLengthError: self = .inputLengthError
        case errSecOutputLengthError: self = .outputLengthError
        case errSecPrivilegeNotSupported: self = .privilegeNotSupported
        case errSecDeviceError: self = .deviceError
        case errSecAttachHandleBusy: self = .attachHandleBusy
        case errSecNotLoggedIn: self = .notLoggedIn
        case errSecAlgorithmMismatch: self = .algorithmMismatch
        case errSecKeyUsageIncorrect: self = .keyUsageIncorrect
        case errSecKeyBlobTypeIncorrect: self = .keyBlobTypeIncorrect
        case errSecKeyHeaderInconsistent: self = .keyHeaderInconsistent
        case errSecUnsupportedKeyFormat: self = .unsupportedKeyFormat
        case errSecUnsupportedKeySize: self = .unsupportedKeySize
        case errSecInvalidKeyUsageMask: self = .invalidKeyUsageMask
        case errSecUnsupportedKeyUsageMask: self = .unsupportedKeyUsageMask
        case errSecInvalidKeyAttributeMask: self = .invalidKeyAttributeMask
        case errSecUnsupportedKeyAttributeMask: self = .unsupportedKeyAttributeMask
        case errSecInvalidKeyLabel: self = .invalidKeyLabel
        case errSecUnsupportedKeyLabel: self = .unsupportedKeyLabel
        case errSecInvalidKeyFormat: self = .invalidKeyFormat
        case errSecUnsupportedVectorOfBuffers: self = .unsupportedVectorOfBuffers
        case errSecInvalidInputVector: self = .invalidInputVector
        case errSecInvalidOutputVector: self = .invalidOutputVector
        case errSecInvalidContext: self = .invalidContext
        case errSecInvalidAlgorithm: self = .invalidAlgorithm
        case errSecInvalidAttributeKey: self = .invalidAttributeKey
        case errSecMissingAttributeKey: self = .missingAttributeKey
        case errSecInvalidAttributeInitVector: self = .invalidAttributeInitVector
        case errSecMissingAttributeInitVector: self = .missingAttributeInitVector
        case errSecInvalidAttributeSalt: self = .invalidAttributeSalt
        case errSecMissingAttributeSalt: self = .missingAttributeSalt
        case errSecInvalidAttributePadding: self = .invalidAttributePadding
        case errSecMissingAttributePadding: self = .missingAttributePadding
        case errSecInvalidAttributeRandom: self = .invalidAttributeRandom
        case errSecMissingAttributeRandom: self = .missingAttributeRandom
        case errSecInvalidAttributeSeed: self = .invalidAttributeSeed
        case errSecMissingAttributeSeed: self = .missingAttributeSeed
        case errSecInvalidAttributePassphrase: self = .invalidAttributePassphrase
        case errSecMissingAttributePassphrase: self = .missingAttributePassphrase
        case errSecInvalidAttributeKeyLength: self = .invalidAttributeKeyLength
        case errSecMissingAttributeKeyLength: self = .missingAttributeKeyLength
        case errSecInvalidAttributeBlockSize: self = .invalidAttributeBlockSize
        case errSecMissingAttributeBlockSize: self = .missingAttributeBlockSize
        case errSecInvalidAttributeOutputSize: self = .invalidAttributeOutputSize
        case errSecMissingAttributeOutputSize: self = .missingAttributeOutputSize
        case errSecInvalidAttributeRounds: self = .invalidAttributeRounds
        case errSecMissingAttributeRounds: self = .missingAttributeRounds
        case errSecInvalidAlgorithmParms: self = .invalidAlgorithmParms
        case errSecMissingAlgorithmParms: self = .missingAlgorithmParms
        case errSecInvalidAttributeLabel: self = .invalidAttributeLabel
        case errSecMissingAttributeLabel: self = .missingAttributeLabel
        case errSecInvalidAttributeKeyType: self = .invalidAttributeKeyType
        case errSecMissingAttributeKeyType: self = .missingAttributeKeyType
        case errSecInvalidAttributeMode: self = .invalidAttributeMode
        case errSecMissingAttributeMode: self = .missingAttributeMode
        case errSecInvalidAttributeEffectiveBits: self = .invalidAttributeEffectiveBits
        case errSecMissingAttributeEffectiveBits: self = .missingAttributeEffectiveBits
        case errSecInvalidAttributeStartDate: self = .invalidAttributeStartDate
        case errSecMissingAttributeStartDate: self = .missingAttributeStartDate
        case errSecInvalidAttributeEndDate: self = .invalidAttributeEndDate
        case errSecMissingAttributeEndDate: self = .missingAttributeEndDate
        case errSecInvalidAttributeVersion: self = .invalidAttributeVersion
        case errSecMissingAttributeVersion: self = .missingAttributeVersion
        case errSecInvalidAttributePrime: self = .invalidAttributePrime
        case errSecMissingAttributePrime: self = .missingAttributePrime
        case errSecInvalidAttributeBase: self = .invalidAttributeBase
        case errSecMissingAttributeBase: self = .missingAttributeBase
        case errSecInvalidAttributeSubprime: self = .invalidAttributeSubprime
        case errSecMissingAttributeSubprime: self = .missingAttributeSubprime
        case errSecInvalidAttributeIterationCount: self = .invalidAttributeIterationCount
        case errSecMissingAttributeIterationCount: self = .missingAttributeIterationCount
        case errSecInvalidAttributeDLDBHandle: self = .invalidAttributeDLDBHandle
        case errSecMissingAttributeDLDBHandle: self = .missingAttributeDLDBHandle
        case errSecInvalidAttributeAccessCredentials: self = .invalidAttributeAccessCredentials
        case errSecMissingAttributeAccessCredentials: self = .missingAttributeAccessCredentials
        case errSecInvalidAttributePublicKeyFormat: self = .invalidAttributePublicKeyFormat
        case errSecMissingAttributePublicKeyFormat: self = .missingAttributePublicKeyFormat
        case errSecInvalidAttributePrivateKeyFormat: self = .invalidAttributePrivateKeyFormat
        case errSecMissingAttributePrivateKeyFormat: self = .missingAttributePrivateKeyFormat
        case errSecInvalidAttributeSymmetricKeyFormat: self = .invalidAttributeSymmetricKeyFormat
        case errSecMissingAttributeSymmetricKeyFormat: self = .missingAttributeSymmetricKeyFormat
        case errSecInvalidAttributeWrappedKeyFormat: self = .invalidAttributeWrappedKeyFormat
        case errSecMissingAttributeWrappedKeyFormat: self = .missingAttributeWrappedKeyFormat
        case errSecStagedOperationInProgress: self = .stagedOperationInProgress
        case errSecStagedOperationNotStarted: self = .stagedOperationNotStarted
        case errSecVerifyFailed: self = .verifyFailed
        case errSecQuerySizeUnknown: self = .querySizeUnknown
        case errSecBlockSizeMismatch: self = .blockSizeMismatch
        case errSecPublicKeyInconsistent: self = .publicKeyInconsistent
        case errSecDeviceVerifyFailed: self = .deviceVerifyFailed
        case errSecInvalidLoginName: self = .invalidLoginName
        case errSecAlreadyLoggedIn: self = .alreadyLoggedIn
        case errSecInvalidDigestAlgorithm: self = .invalidDigestAlgorithm
        case errSecInvalidCRLGroup: self = .invalidCRLGroup
        case errSecCertificateCannotOperate: self = .certificateCannotOperate
        case errSecCertificateExpired: self = .certificateExpired
        case errSecCertificateNotValidYet: self = .certificateNotValidYet
        case errSecCertificateRevoked: self = .certificateRevoked
        case errSecCertificateSuspended: self = .certificateSuspended
        case errSecInsufficientCredentials: self = .insufficientCredentials
        case errSecInvalidAction: self = .invalidAction
        case errSecInvalidAuthority: self = .invalidAuthority
        case errSecVerifyActionFailed: self = .verifyActionFailed
        case errSecInvalidCertAuthority: self = .invalidCertAuthority
        case errSecInvaldCRLAuthority: self = .invaldCRLAuthority
        case errSecInvalidCRLEncoding: self = .invalidCRLEncoding
        case errSecInvalidCRLType: self = .invalidCRLType
        case errSecInvalidCRL: self = .invalidCRL
        case errSecInvalidFormType: self = .invalidFormType
        case errSecInvalidID: self = .invalidID
        case errSecInvalidIdentifier: self = .invalidIdentifier
        case errSecInvalidIndex: self = .invalidIndex
        case errSecInvalidPolicyIdentifiers: self = .invalidPolicyIdentifiers
        case errSecInvalidTimeString: self = .invalidTimeString
        case errSecInvalidReason: self = .invalidReason
        case errSecInvalidRequestInputs: self = .invalidRequestInputs
        case errSecInvalidResponseVector: self = .invalidResponseVector
        case errSecInvalidStopOnPolicy: self = .invalidStopOnPolicy
        case errSecInvalidTuple: self = .invalidTuple
        case errSecMultipleValuesUnsupported: self = .multipleValuesUnsupported
        case errSecNotTrusted: self = .notTrusted
        case errSecNoDefaultAuthority: self = .noDefaultAuthority
        case errSecRejectedForm: self = .rejectedForm
        case errSecRequestLost: self = .requestLost
        case errSecRequestRejected: self = .requestRejected
        case errSecUnsupportedAddressType: self = .unsupportedAddressType
        case errSecUnsupportedService: self = .unsupportedService
        case errSecInvalidTupleGroup: self = .invalidTupleGroup
        case errSecInvalidBaseACLs: self = .invalidBaseACLs
        case errSecInvalidTupleCredendtials: self = .invalidTupleCredendtials
        case errSecInvalidEncoding: self = .invalidEncoding
        case errSecInvalidValidityPeriod: self = .invalidValidityPeriod
        case errSecInvalidRequestor: self = .invalidRequestor
        case errSecRequestDescriptor: self = .requestDescriptor
        case errSecInvalidBundleInfo: self = .invalidBundleInfo
        case errSecInvalidCRLIndex: self = .invalidCRLIndex
        case errSecNoFieldValues: self = .noFieldValues
        case errSecUnsupportedFieldFormat: self = .unsupportedFieldFormat
        case errSecUnsupportedIndexInfo: self = .unsupportedIndexInfo
        case errSecUnsupportedLocality: self = .unsupportedLocality
        case errSecUnsupportedNumAttributes: self = .unsupportedNumAttributes
        case errSecUnsupportedNumIndexes: self = .unsupportedNumIndexes
        case errSecUnsupportedNumRecordTypes: self = .unsupportedNumRecordTypes
        case errSecFieldSpecifiedMultiple: self = .fieldSpecifiedMultiple
        case errSecIncompatibleFieldFormat: self = .incompatibleFieldFormat
        case errSecInvalidParsingModule: self = .invalidParsingModule
        case errSecDatabaseLocked: self = .databaseLocked
        case errSecDatastoreIsOpen: self = .datastoreIsOpen
        case errSecMissingValue: self = .missingValue
        case errSecUnsupportedQueryLimits: self = .unsupportedQueryLimits
        case errSecUnsupportedNumSelectionPreds: self = .unsupportedNumSelectionPreds
        case errSecUnsupportedOperator: self = .unsupportedOperator
        case errSecInvalidDBLocation: self = .invalidDBLocation
        case errSecInvalidAccessRequest: self = .invalidAccessRequest
        case errSecInvalidIndexInfo: self = .invalidIndexInfo
        case errSecInvalidNewOwner: self = .invalidNewOwner
        case errSecInvalidModifyMode: self = .invalidModifyMode
        case errSecMissingRequiredExtension: self = .missingRequiredExtension
        case errSecExtendedKeyUsageNotCritical: self = .extendedKeyUsageNotCritical
        case errSecTimestampMissing: self = .timestampMissing
        case errSecTimestampInvalid: self = .timestampInvalid
        case errSecTimestampNotTrusted: self = .timestampNotTrusted
        case errSecTimestampServiceNotAvailable: self = .timestampServiceNotAvailable
        case errSecTimestampBadAlg: self = .timestampBadAlg
        case errSecTimestampBadRequest: self = .timestampBadRequest
        case errSecTimestampBadDataFormat: self = .timestampBadDataFormat
        case errSecTimestampTimeNotAvailable: self = .timestampTimeNotAvailable
        case errSecTimestampUnacceptedPolicy: self = .timestampUnacceptedPolicy
        case errSecTimestampUnacceptedExtension: self = .timestampUnacceptedExtension
        case errSecTimestampAddInfoNotAvailable: self = .timestampAddInfoNotAvailable
        case errSecTimestampSystemFailure: self = .timestampSystemFailure
        case errSecSigningTimeMissing: self = .signingTimeMissing
        case errSecTimestampRejection: self = .timestampRejection
        case errSecTimestampWaiting: self = .timestampWaiting
        case errSecTimestampRevocationWarning: self = .timestampRevocationWarning
        case errSecTimestampRevocationNotification: self = .timestampRevocationNotification
        default: self = .unexpected
        }
    }
    
    var rawValue: OSStatus {
        switch self {
        case .unimplemented: return errSecUnimplemented
        case .diskFull: return errSecDiskFull
        case .io: return errSecIO
        case .opWr: return errSecOpWr
        case .param: return errSecParam
        case .wrPerm: return errSecWrPerm
        case .allocate: return errSecAllocate
        case .userCanceled: return errSecUserCanceled
        case .badReq: return errSecBadReq
        case .internalComponent: return errSecInternalComponent
        case .coreFoundationUnknown: return errSecCoreFoundationUnknown
        case .missingEntitlement: return errSecMissingEntitlement
        case .notAvailable: return errSecNotAvailable
        case .readOnly: return errSecReadOnly
        case .authFailed: return errSecAuthFailed
        case .noSuchKeychain: return errSecNoSuchKeychain
        case .invalidKeychain: return errSecInvalidKeychain
        case .duplicateKeychain: return errSecDuplicateKeychain
        case .duplicateCallback: return errSecDuplicateCallback
        case .invalidCallback: return errSecInvalidCallback
        case .duplicateItem: return errSecDuplicateItem
        case .itemNotFound: return errSecItemNotFound
        case .bufferTooSmall: return errSecBufferTooSmall
        case .dataTooLarge: return errSecDataTooLarge
        case .noSuchAttr: return errSecNoSuchAttr
        case .invalidItemRef: return errSecInvalidItemRef
        case .invalidSearchRef: return errSecInvalidSearchRef
        case .noSuchClass: return errSecNoSuchClass
        case .noDefaultKeychain: return errSecNoDefaultKeychain
        case .interactionNotAllowed: return errSecInteractionNotAllowed
        case .readOnlyAttr: return errSecReadOnlyAttr
        case .wrongSecVersion: return errSecWrongSecVersion
        case .keySizeNotAllowed: return errSecKeySizeNotAllowed
        case .noStorageModule: return errSecNoStorageModule
        case .noCertificateModule: return errSecNoCertificateModule
        case .noPolicyModule: return errSecNoPolicyModule
        case .interactionRequired: return errSecInteractionRequired
        case .dataNotAvailable: return errSecDataNotAvailable
        case .dataNotModifiable: return errSecDataNotModifiable
        case .createChainFailed: return errSecCreateChainFailed
        case .invalidPrefsDomain: return errSecInvalidPrefsDomain
        case .inDarkWake: return errSecInDarkWake
        case .aclNotSimple: return errSecACLNotSimple
        case .policyNotFound: return errSecPolicyNotFound
        case .invalidTrustSetting: return errSecInvalidTrustSetting
        case .noAccessForItem: return errSecNoAccessForItem
        case .invalidOwnerEdit: return errSecInvalidOwnerEdit
        case .trustNotAvailable: return errSecTrustNotAvailable
        case .unsupportedFormat: return errSecUnsupportedFormat
        case .unknownFormat: return errSecUnknownFormat
        case .keyIsSensitive: return errSecKeyIsSensitive
        case .multiplePrivKeys: return errSecMultiplePrivKeys
        case .passphraseRequired: return errSecPassphraseRequired
        case .invalidPasswordRef: return errSecInvalidPasswordRef
        case .invalidTrustSettings: return errSecInvalidTrustSettings
        case .noTrustSettings: return errSecNoTrustSettings
        case .pkcs12VerifyFailure: return errSecPkcs12VerifyFailure
        case .notSigner: return errSecNotSigner
        case .decode: return errSecDecode
        case .serviceNotAvailable: return errSecServiceNotAvailable
        case .insufficientClientID: return errSecInsufficientClientID
        case .deviceReset: return errSecDeviceReset
        case .deviceFailed: return errSecDeviceFailed
        case .appleAddAppACLSubject: return errSecAppleAddAppACLSubject
        case .applePublicKeyIncomplete: return errSecApplePublicKeyIncomplete
        case .appleSignatureMismatch: return errSecAppleSignatureMismatch
        case .appleInvalidKeyStartDate: return errSecAppleInvalidKeyStartDate
        case .appleInvalidKeyEndDate: return errSecAppleInvalidKeyEndDate
        case .conversionError: return errSecConversionError
        case .appleSSLv2Rollback: return errSecAppleSSLv2Rollback
        case .quotaExceeded: return errSecQuotaExceeded
        case .fileTooBig: return errSecFileTooBig
        case .invalidDatabaseBlob: return errSecInvalidDatabaseBlob
        case .invalidKeyBlob: return errSecInvalidKeyBlob
        case .incompatibleDatabaseBlob: return errSecIncompatibleDatabaseBlob
        case .incompatibleKeyBlob: return errSecIncompatibleKeyBlob
        case .hostNameMismatch: return errSecHostNameMismatch
        case .unknownCriticalExtensionFlag: return errSecUnknownCriticalExtensionFlag
        case .noBasicConstraints: return errSecNoBasicConstraints
        case .noBasicConstraintsCA: return errSecNoBasicConstraintsCA
        case .invalidAuthorityKeyID: return errSecInvalidAuthorityKeyID
        case .invalidSubjectKeyID: return errSecInvalidSubjectKeyID
        case .invalidKeyUsageForPolicy: return errSecInvalidKeyUsageForPolicy
        case .invalidExtendedKeyUsage: return errSecInvalidExtendedKeyUsage
        case .invalidIDLinkage: return errSecInvalidIDLinkage
        case .pathLengthConstraintExceeded: return errSecPathLengthConstraintExceeded
        case .invalidRoot: return errSecInvalidRoot
        case .crlExpired: return errSecCRLExpired
        case .crlNotValidYet: return errSecCRLNotValidYet
        case .crlNotFound: return errSecCRLNotFound
        case .crlServerDown: return errSecCRLServerDown
        case .crlBadURI: return errSecCRLBadURI
        case .unknownCertExtension: return errSecUnknownCertExtension
        case .unknownCRLExtension: return errSecUnknownCRLExtension
        case .crlNotTrusted: return errSecCRLNotTrusted
        case .crlPolicyFailed: return errSecCRLPolicyFailed
        case .idPFailure: return errSecIDPFailure
        case .smimeEmailAddressesNotFound: return errSecSMIMEEmailAddressesNotFound
        case .smimeBadExtendedKeyUsage: return errSecSMIMEBadExtendedKeyUsage
        case .smimeBadKeyUsage: return errSecSMIMEBadKeyUsage
        case .smimeKeyUsageNotCritical: return errSecSMIMEKeyUsageNotCritical
        case .smimeNoEmailAddress: return errSecSMIMENoEmailAddress
        case .smimeSubjAltNameNotCritical: return errSecSMIMESubjAltNameNotCritical
        case .sslBadExtendedKeyUsage: return errSecSSLBadExtendedKeyUsage
        case .ocspBadResponse: return errSecOCSPBadResponse
        case .ocspBadRequest: return errSecOCSPBadRequest
        case .ocspUnavailable: return errSecOCSPUnavailable
        case .ocspStatusUnrecognized: return errSecOCSPStatusUnrecognized
        case .endOfData: return errSecEndOfData
        case .incompleteCertRevocationCheck: return errSecIncompleteCertRevocationCheck
        case .networkFailure: return errSecNetworkFailure
        case .ocspNotTrustedToAnchor: return errSecOCSPNotTrustedToAnchor
        case .recordModified: return errSecRecordModified
        case .ocspSignatureError: return errSecOCSPSignatureError
        case .ocspNoSigner: return errSecOCSPNoSigner
        case .ocspResponderMalformedReq: return errSecOCSPResponderMalformedReq
        case .ocspResponderInternalError: return errSecOCSPResponderInternalError
        case .ocspResponderTryLater: return errSecOCSPResponderTryLater
        case .ocspResponderSignatureRequired: return errSecOCSPResponderSignatureRequired
        case .ocspResponderUnauthorized: return errSecOCSPResponderUnauthorized
        case .ocspResponseNonceMismatch: return errSecOCSPResponseNonceMismatch
        case .codeSigningBadCertChainLength: return errSecCodeSigningBadCertChainLength
        case .codeSigningNoBasicConstraints: return errSecCodeSigningNoBasicConstraints
        case .codeSigningBadPathLengthConstraint: return errSecCodeSigningBadPathLengthConstraint
        case .codeSigningNoExtendedKeyUsage: return errSecCodeSigningNoExtendedKeyUsage
        case .codeSigningDevelopment: return errSecCodeSigningDevelopment
        case .resourceSignBadCertChainLength: return errSecResourceSignBadCertChainLength
        case .resourceSignBadExtKeyUsage: return errSecResourceSignBadExtKeyUsage
        case .trustSettingDeny: return errSecTrustSettingDeny
        case .invalidSubjectName: return errSecInvalidSubjectName
        case .unknownQualifiedCertStatement: return errSecUnknownQualifiedCertStatement
        case .mobileMeRequestQueued: return errSecMobileMeRequestQueued
        case .mobileMeRequestRedirected: return errSecMobileMeRequestRedirected
        case .mobileMeServerError: return errSecMobileMeServerError
        case .mobileMeServerNotAvailable: return errSecMobileMeServerNotAvailable
        case .mobileMeServerAlreadyExists: return errSecMobileMeServerAlreadyExists
        case .mobileMeServerServiceErr: return errSecMobileMeServerServiceErr
        case .mobileMeRequestAlreadyPending: return errSecMobileMeRequestAlreadyPending
        case .mobileMeNoRequestPending: return errSecMobileMeNoRequestPending
        case .mobileMeCSRVerifyFailure: return errSecMobileMeCSRVerifyFailure
        case .mobileMeFailedConsistencyCheck: return errSecMobileMeFailedConsistencyCheck
        case .notInitialized: return errSecNotInitialized
        case .invalidHandleUsage: return errSecInvalidHandleUsage
        case .pvcReferentNotFound: return errSecPVCReferentNotFound
        case .functionIntegrityFail: return errSecFunctionIntegrityFail
        case .internalError: return errSecInternalError
        case .memoryError: return errSecMemoryError
        case .invalidData: return errSecInvalidData
        case .mdsError: return errSecMDSError
        case .invalidPointer: return errSecInvalidPointer
        case .selfCheckFailed: return errSecSelfCheckFailed
        case .functionFailed: return errSecFunctionFailed
        case .moduleManifestVerifyFailed: return errSecModuleManifestVerifyFailed
        case .invalidGUID: return errSecInvalidGUID
        case .invalidHandle: return errSecInvalidHandle
        case .invalidDBList: return errSecInvalidDBList
        case .invalidPassthroughID: return errSecInvalidPassthroughID
        case .invalidNetworkAddress: return errSecInvalidNetworkAddress
        case .crlAlreadySigned: return errSecCRLAlreadySigned
        case .invalidNumberOfFields: return errSecInvalidNumberOfFields
        case .verificationFailure: return errSecVerificationFailure
        case .unknownTag: return errSecUnknownTag
        case .invalidSignature: return errSecInvalidSignature
        case .invalidName: return errSecInvalidName
        case .invalidCertificateRef: return errSecInvalidCertificateRef
        case .invalidCertificateGroup: return errSecInvalidCertificateGroup
        case .tagNotFound: return errSecTagNotFound
        case .invalidQuery: return errSecInvalidQuery
        case .invalidValue: return errSecInvalidValue
        case .callbackFailed: return errSecCallbackFailed
        case .aclDeleteFailed: return errSecACLDeleteFailed
        case .aclReplaceFailed: return errSecACLReplaceFailed
        case .aclAddFailed: return errSecACLAddFailed
        case .aclChangeFailed: return errSecACLChangeFailed
        case .invalidAccessCredentials: return errSecInvalidAccessCredentials
        case .invalidRecord: return errSecInvalidRecord
        case .invalidACL: return errSecInvalidACL
        case .invalidSampleValue: return errSecInvalidSampleValue
        case .incompatibleVersion: return errSecIncompatibleVersion
        case .privilegeNotGranted: return errSecPrivilegeNotGranted
        case .invalidScope: return errSecInvalidScope
        case .pvcAlreadyConfigured: return errSecPVCAlreadyConfigured
        case .invalidPVC: return errSecInvalidPVC
        case .emmLoadFailed: return errSecEMMLoadFailed
        case .emmUnloadFailed: return errSecEMMUnloadFailed
        case .addinLoadFailed: return errSecAddinLoadFailed
        case .invalidKeyRef: return errSecInvalidKeyRef
        case .invalidKeyHierarchy: return errSecInvalidKeyHierarchy
        case .addinUnloadFailed: return errSecAddinUnloadFailed
        case .libraryReferenceNotFound: return errSecLibraryReferenceNotFound
        case .invalidAddinFunctionTable: return errSecInvalidAddinFunctionTable
        case .invalidServiceMask: return errSecInvalidServiceMask
        case .moduleNotLoaded: return errSecModuleNotLoaded
        case .invalidSubServiceID: return errSecInvalidSubServiceID
        case .attributeNotInContext: return errSecAttributeNotInContext
        case .moduleManagerInitializeFailed: return errSecModuleManagerInitializeFailed
        case .moduleManagerNotFound: return errSecModuleManagerNotFound
        case .eventNotificationCallbackNotFound: return errSecEventNotificationCallbackNotFound
        case .inputLengthError: return errSecInputLengthError
        case .outputLengthError: return errSecOutputLengthError
        case .privilegeNotSupported: return errSecPrivilegeNotSupported
        case .deviceError: return errSecDeviceError
        case .attachHandleBusy: return errSecAttachHandleBusy
        case .notLoggedIn: return errSecNotLoggedIn
        case .algorithmMismatch: return errSecAlgorithmMismatch
        case .keyUsageIncorrect: return errSecKeyUsageIncorrect
        case .keyBlobTypeIncorrect: return errSecKeyBlobTypeIncorrect
        case .keyHeaderInconsistent: return errSecKeyHeaderInconsistent
        case .unsupportedKeyFormat: return errSecUnsupportedKeyFormat
        case .unsupportedKeySize: return errSecUnsupportedKeySize
        case .invalidKeyUsageMask: return errSecInvalidKeyUsageMask
        case .unsupportedKeyUsageMask: return errSecUnsupportedKeyUsageMask
        case .invalidKeyAttributeMask: return errSecInvalidKeyAttributeMask
        case .unsupportedKeyAttributeMask: return errSecUnsupportedKeyAttributeMask
        case .invalidKeyLabel: return errSecInvalidKeyLabel
        case .unsupportedKeyLabel: return errSecUnsupportedKeyLabel
        case .invalidKeyFormat: return errSecInvalidKeyFormat
        case .unsupportedVectorOfBuffers: return errSecUnsupportedVectorOfBuffers
        case .invalidInputVector: return errSecInvalidInputVector
        case .invalidOutputVector: return errSecInvalidOutputVector
        case .invalidContext: return errSecInvalidContext
        case .invalidAlgorithm: return errSecInvalidAlgorithm
        case .invalidAttributeKey: return errSecInvalidAttributeKey
        case .missingAttributeKey: return errSecMissingAttributeKey
        case .invalidAttributeInitVector: return errSecInvalidAttributeInitVector
        case .missingAttributeInitVector: return errSecMissingAttributeInitVector
        case .invalidAttributeSalt: return errSecInvalidAttributeSalt
        case .missingAttributeSalt: return errSecMissingAttributeSalt
        case .invalidAttributePadding: return errSecInvalidAttributePadding
        case .missingAttributePadding: return errSecMissingAttributePadding
        case .invalidAttributeRandom: return errSecInvalidAttributeRandom
        case .missingAttributeRandom: return errSecMissingAttributeRandom
        case .invalidAttributeSeed: return errSecInvalidAttributeSeed
        case .missingAttributeSeed: return errSecMissingAttributeSeed
        case .invalidAttributePassphrase: return errSecInvalidAttributePassphrase
        case .missingAttributePassphrase: return errSecMissingAttributePassphrase
        case .invalidAttributeKeyLength: return errSecInvalidAttributeKeyLength
        case .missingAttributeKeyLength: return errSecMissingAttributeKeyLength
        case .invalidAttributeBlockSize: return errSecInvalidAttributeBlockSize
        case .missingAttributeBlockSize: return errSecMissingAttributeBlockSize
        case .invalidAttributeOutputSize: return errSecInvalidAttributeOutputSize
        case .missingAttributeOutputSize: return errSecMissingAttributeOutputSize
        case .invalidAttributeRounds: return errSecInvalidAttributeRounds
        case .missingAttributeRounds: return errSecMissingAttributeRounds
        case .invalidAlgorithmParms: return errSecInvalidAlgorithmParms
        case .missingAlgorithmParms: return errSecMissingAlgorithmParms
        case .invalidAttributeLabel: return errSecInvalidAttributeLabel
        case .missingAttributeLabel: return errSecMissingAttributeLabel
        case .invalidAttributeKeyType: return errSecInvalidAttributeKeyType
        case .missingAttributeKeyType: return errSecMissingAttributeKeyType
        case .invalidAttributeMode: return errSecInvalidAttributeMode
        case .missingAttributeMode: return errSecMissingAttributeMode
        case .invalidAttributeEffectiveBits: return errSecInvalidAttributeEffectiveBits
        case .missingAttributeEffectiveBits: return errSecMissingAttributeEffectiveBits
        case .invalidAttributeStartDate: return errSecInvalidAttributeStartDate
        case .missingAttributeStartDate: return errSecMissingAttributeStartDate
        case .invalidAttributeEndDate: return errSecInvalidAttributeEndDate
        case .missingAttributeEndDate: return errSecMissingAttributeEndDate
        case .invalidAttributeVersion: return errSecInvalidAttributeVersion
        case .missingAttributeVersion: return errSecMissingAttributeVersion
        case .invalidAttributePrime: return errSecInvalidAttributePrime
        case .missingAttributePrime: return errSecMissingAttributePrime
        case .invalidAttributeBase: return errSecInvalidAttributeBase
        case .missingAttributeBase: return errSecMissingAttributeBase
        case .invalidAttributeSubprime: return errSecInvalidAttributeSubprime
        case .missingAttributeSubprime: return errSecMissingAttributeSubprime
        case .invalidAttributeIterationCount: return errSecInvalidAttributeIterationCount
        case .missingAttributeIterationCount: return errSecMissingAttributeIterationCount
        case .invalidAttributeDLDBHandle: return errSecInvalidAttributeDLDBHandle
        case .missingAttributeDLDBHandle: return errSecMissingAttributeDLDBHandle
        case .invalidAttributeAccessCredentials: return errSecInvalidAttributeAccessCredentials
        case .missingAttributeAccessCredentials: return errSecMissingAttributeAccessCredentials
        case .invalidAttributePublicKeyFormat: return errSecInvalidAttributePublicKeyFormat
        case .missingAttributePublicKeyFormat: return errSecMissingAttributePublicKeyFormat
        case .invalidAttributePrivateKeyFormat: return errSecInvalidAttributePrivateKeyFormat
        case .missingAttributePrivateKeyFormat: return errSecMissingAttributePrivateKeyFormat
        case .invalidAttributeSymmetricKeyFormat: return errSecInvalidAttributeSymmetricKeyFormat
        case .missingAttributeSymmetricKeyFormat: return errSecMissingAttributeSymmetricKeyFormat
        case .invalidAttributeWrappedKeyFormat: return errSecInvalidAttributeWrappedKeyFormat
        case .missingAttributeWrappedKeyFormat: return errSecMissingAttributeWrappedKeyFormat
        case .stagedOperationInProgress: return errSecStagedOperationInProgress
        case .stagedOperationNotStarted: return errSecStagedOperationNotStarted
        case .verifyFailed: return errSecVerifyFailed
        case .querySizeUnknown: return errSecQuerySizeUnknown
        case .blockSizeMismatch: return errSecBlockSizeMismatch
        case .publicKeyInconsistent: return errSecPublicKeyInconsistent
        case .deviceVerifyFailed: return errSecDeviceVerifyFailed
        case .invalidLoginName: return errSecInvalidLoginName
        case .alreadyLoggedIn: return errSecAlreadyLoggedIn
        case .invalidDigestAlgorithm: return errSecInvalidDigestAlgorithm
        case .invalidCRLGroup: return errSecInvalidCRLGroup
        case .certificateCannotOperate: return errSecCertificateCannotOperate
        case .certificateExpired: return errSecCertificateExpired
        case .certificateNotValidYet: return errSecCertificateNotValidYet
        case .certificateRevoked: return errSecCertificateRevoked
        case .certificateSuspended: return errSecCertificateSuspended
        case .insufficientCredentials: return errSecInsufficientCredentials
        case .invalidAction: return errSecInvalidAction
        case .invalidAuthority: return errSecInvalidAuthority
        case .verifyActionFailed: return errSecVerifyActionFailed
        case .invalidCertAuthority: return errSecInvalidCertAuthority
        case .invaldCRLAuthority: return errSecInvaldCRLAuthority
        case .invalidCRLEncoding: return errSecInvalidCRLEncoding
        case .invalidCRLType: return errSecInvalidCRLType
        case .invalidCRL: return errSecInvalidCRL
        case .invalidFormType: return errSecInvalidFormType
        case .invalidID: return errSecInvalidID
        case .invalidIdentifier: return errSecInvalidIdentifier
        case .invalidIndex: return errSecInvalidIndex
        case .invalidPolicyIdentifiers: return errSecInvalidPolicyIdentifiers
        case .invalidTimeString: return errSecInvalidTimeString
        case .invalidReason: return errSecInvalidReason
        case .invalidRequestInputs: return errSecInvalidRequestInputs
        case .invalidResponseVector: return errSecInvalidResponseVector
        case .invalidStopOnPolicy: return errSecInvalidStopOnPolicy
        case .invalidTuple: return errSecInvalidTuple
        case .multipleValuesUnsupported: return errSecMultipleValuesUnsupported
        case .notTrusted: return errSecNotTrusted
        case .noDefaultAuthority: return errSecNoDefaultAuthority
        case .rejectedForm: return errSecRejectedForm
        case .requestLost: return errSecRequestLost
        case .requestRejected: return errSecRequestRejected
        case .unsupportedAddressType: return errSecUnsupportedAddressType
        case .unsupportedService: return errSecUnsupportedService
        case .invalidTupleGroup: return errSecInvalidTupleGroup
        case .invalidBaseACLs: return errSecInvalidBaseACLs
        case .invalidTupleCredendtials: return errSecInvalidTupleCredendtials
        case .invalidEncoding: return errSecInvalidEncoding
        case .invalidValidityPeriod: return errSecInvalidValidityPeriod
        case .invalidRequestor: return errSecInvalidRequestor
        case .requestDescriptor: return errSecRequestDescriptor
        case .invalidBundleInfo: return errSecInvalidBundleInfo
        case .invalidCRLIndex: return errSecInvalidCRLIndex
        case .noFieldValues: return errSecNoFieldValues
        case .unsupportedFieldFormat: return errSecUnsupportedFieldFormat
        case .unsupportedIndexInfo: return errSecUnsupportedIndexInfo
        case .unsupportedLocality: return errSecUnsupportedLocality
        case .unsupportedNumAttributes: return errSecUnsupportedNumAttributes
        case .unsupportedNumIndexes: return errSecUnsupportedNumIndexes
        case .unsupportedNumRecordTypes: return errSecUnsupportedNumRecordTypes
        case .fieldSpecifiedMultiple: return errSecFieldSpecifiedMultiple
        case .incompatibleFieldFormat: return errSecIncompatibleFieldFormat
        case .invalidParsingModule: return errSecInvalidParsingModule
        case .databaseLocked: return errSecDatabaseLocked
        case .datastoreIsOpen: return errSecDatastoreIsOpen
        case .missingValue: return errSecMissingValue
        case .unsupportedQueryLimits: return errSecUnsupportedQueryLimits
        case .unsupportedNumSelectionPreds: return errSecUnsupportedNumSelectionPreds
        case .unsupportedOperator: return errSecUnsupportedOperator
        case .invalidDBLocation: return errSecInvalidDBLocation
        case .invalidAccessRequest: return errSecInvalidAccessRequest
        case .invalidIndexInfo: return errSecInvalidIndexInfo
        case .invalidNewOwner: return errSecInvalidNewOwner
        case .invalidModifyMode: return errSecInvalidModifyMode
        case .missingRequiredExtension: return errSecMissingRequiredExtension
        case .extendedKeyUsageNotCritical: return errSecExtendedKeyUsageNotCritical
        case .timestampMissing: return errSecTimestampMissing
        case .timestampInvalid: return errSecTimestampInvalid
        case .timestampNotTrusted: return errSecTimestampNotTrusted
        case .timestampServiceNotAvailable: return errSecTimestampServiceNotAvailable
        case .timestampBadAlg: return errSecTimestampBadAlg
        case .timestampBadRequest: return errSecTimestampBadRequest
        case .timestampBadDataFormat: return errSecTimestampBadDataFormat
        case .timestampTimeNotAvailable: return errSecTimestampTimeNotAvailable
        case .timestampUnacceptedPolicy: return errSecTimestampUnacceptedPolicy
        case .timestampUnacceptedExtension: return errSecTimestampUnacceptedExtension
        case .timestampAddInfoNotAvailable: return errSecTimestampAddInfoNotAvailable
        case .timestampSystemFailure: return errSecTimestampSystemFailure
        case .signingTimeMissing: return errSecSigningTimeMissing
        case .timestampRejection: return errSecTimestampRejection
        case .timestampWaiting: return errSecTimestampWaiting
        case .timestampRevocationWarning: return errSecTimestampRevocationWarning
        case .timestampRevocationNotification: return errSecTimestampRevocationNotification
        case .unexpected: return -99999
        }
    }
    
}
