//
//  KeychainAttribute.swift
//  OpenVPN Adapter
//
//  Created by Sergey Abramchuk on 01.09.17.
//
//

import Foundation
import Security

// MARK: Keychain Attributes

typealias KeychainAttributes = [KeychainAttribute : Any]

enum KeychainAttribute {
    case accessGroup
    case label
    case type
    case service
    case account
    case generic
    case tag
    case keyType
    case keyClass
    case keySize
}

extension KeychainAttribute: RawRepresentable {

    init?(rawValue: String) {
        switch String(rawValue) {
        case String(kSecAttrAccessGroup): self = .accessGroup
        case String(kSecAttrLabel): self = .label
        case String(kSecAttrType): self = .type
        case String(kSecAttrService): self = .service
        case String(kSecAttrAccount): self = .account
        case String(kSecAttrGeneric): self = .generic
        case String(kSecAttrApplicationTag): self = .tag
        case String(kSecAttrKeyType): self = .keyType
        case String(kSecAttrKeyClass): self = .keyClass
        case String(kSecAttrKeySizeInBits): self = .keySize
        default: return nil
        }
    }
    
    var rawValue: String {
        switch self {
        case .accessGroup: return String(kSecAttrAccessGroup)
        case .label: return String(kSecAttrLabel)
        case .type: return String(kSecAttrType)
        case .service: return String(kSecAttrService)
        case .account: return String(kSecAttrAccount)
        case .generic: return String(kSecAttrGeneric)
        case .tag: return String(kSecAttrApplicationTag)
        case .keyType: return String(kSecAttrKeyType)
        case .keyClass: return String(kSecAttrKeyClass)
        case .keySize: return String(kSecAttrKeySizeInBits)
        }
    }
    
}

// MARK: - Keychain Key Types

enum KeyType {
    case RSA
    case EC
}

extension KeyType: RawRepresentable {
    
    init?(rawValue: String) {
        switch rawValue {
        case String(kSecAttrKeyTypeRSA): self = .RSA
        case String(kSecAttrKeyTypeEC): self = .EC
        default: return nil
        }
    }
    
    var rawValue: String {
        switch self {
        case .RSA: return String(kSecAttrKeyTypeRSA)
        case .EC: return String(kSecAttrKeyTypeEC)
        }
    }
    
}

// MARK: - Keychain Key Classes

enum KeyClass {
    case privateKey
    case publicKey
}

extension KeyClass: RawRepresentable {
    init?(rawValue: String) {
        switch rawValue {
        case String(kSecAttrKeyClassPrivate): self = .privateKey
        case String(kSecAttrKeyClassPublic): self = .publicKey
        default: return nil
        }
    }
    
    var rawValue: String {
        switch self {
        case .privateKey: return String(kSecAttrKeyClassPrivate)
        case .publicKey: return String(kSecAttrKeyClassPublic)
        }
    }
}
