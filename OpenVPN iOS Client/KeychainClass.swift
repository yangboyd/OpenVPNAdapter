//
//  KeychainClass.swift
//  OpenVPN Adapter
//
//  Created by Sergey Abramchuk on 01.09.17.
//
//

import Foundation
import Security

enum KeychainClass {
    case password
    case certificate
    case key
}

extension KeychainClass: RawRepresentable {
    
    init?(rawValue: String) {
        switch rawValue {
        case String(kSecClassGenericPassword): self = .password
        case String(kSecClassCertificate): self = .certificate
        case String(kSecClassKey): self = .key
        default: return nil            
        }
    }
    
    var rawValue: String {
        switch self {
        case .password: return String(kSecClassGenericPassword)
        case .certificate: return String(kSecClassCertificate)
        case .key: return String(kSecClassKey)
        }
    }
    
}
