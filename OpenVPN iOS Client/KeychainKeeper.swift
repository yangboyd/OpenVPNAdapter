//
//  KeychainKeeper.swift
//  OpenVPN Adapter
//
//  Created by Sergey Abramchuk on 01.09.17.
//
//

import Foundation
import Security

struct KeychainKeeper {
    
    typealias AddFindOperation = (CFDictionary, UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus
    typealias UpdateOperation = (CFDictionary, CFDictionary) -> OSStatus
    typealias DeleteOperation = (CFDictionary) -> OSStatus
    
    let accessGroup: String?
    
    func set(item: KeychainClass, value: Data, with attributes: KeychainAttributes) throws -> Data {
        var query: [String: Any] = [
            String(kSecClass) : item.rawValue,
            String(kSecReturnPersistentRef): kCFBooleanTrue
        ]
        
        if let accessGroup = self.accessGroup {
            query[String(kSecAttrAccessGroup)] = accessGroup
        }
        
        switch item {
        case .password, .key:
            query[String(kSecValueData)] = value
        case .certificate:
            guard let certificate = SecCertificateCreateWithData(nil, value as CFData) else { throw KeychainError.unknownFormat }
            query[String(kSecValueRef)] = certificate
        }
        
        attributes.forEach { (key, value) in query[key.rawValue] = value }
        
        let result: Result<Data?, KeychainError> = perform(operation: SecItemAdd, query: query)
        
        switch result {
        case .success(let .some(data)): return data
        case .failure(let error): throw error
        default: throw KeychainError.unexpected
        }
    }
    
    func exist(item: KeychainClass, with attributes: KeychainAttributes) throws -> Bool {
        var query: [String: Any] = [
            String(kSecClass) : item.rawValue,
            String(kSecUseAuthenticationUI) : String(kSecUseAuthenticationUIFail)
        ]
        
        if let accessGroup = self.accessGroup {
            query[String(kSecAttrAccessGroup)] = accessGroup
        }
        
        attributes.forEach { (key, value) in query[key.rawValue] = value }
        
        let result: Result<Data?, KeychainError> = perform(operation: SecItemCopyMatching, query: query)
        
        switch result {
        case .success: return true
        case .failure(let error) where error == .itemNotFound: return false
        case .failure(let error): throw error
        }
    }
    
    func find(item: KeychainClass, with attributes: KeychainAttributes) throws -> (data: Data, attributes: KeychainAttributes) {
        let reference = try ref(item: item, with: attributes)
        let found = try find(item: item, with: reference)

        return (data: found.data, attributes: found.attributes)
    }
    
    func find(item: KeychainClass, with ref: Data) throws -> (data: Data, attributes: KeychainAttributes) {
        var query: [String: Any] = [
            String(kSecClass): item.rawValue,
            String(kSecValuePersistentRef): ref,
            String(kSecUseAuthenticationUI) : String(kSecUseAuthenticationUIFail),
            String(kSecReturnAttributes) : kCFBooleanTrue,
            String(kSecReturnData) : kCFBooleanTrue
        ]
        
        if let accessGroup = self.accessGroup {
            query[String(kSecAttrAccessGroup)] = accessGroup
        }
        
        let result: Result<[String : Any]?, KeychainError> = perform(operation: SecItemCopyMatching, query: query)
        
        switch result {
        case .success(var .some(result)):
            guard let data = result.removeValue(forKey: String(kSecValueData)) as? Data else { throw KeychainError.missingValue }
            
            let attributes: KeychainAttributes = Dictionary(uniqueKeysWithValues: result.flatMap { (key, value) in
                guard let attribute = KeychainAttribute(rawValue: key) else { return nil }
                return (attribute, value)
            })
            
            return (data, attributes)
        case .failure(let error): throw error
        default: throw KeychainError.unexpected
        }
    }
    
    func ref(item: KeychainClass, with attributes: KeychainAttributes) throws -> Data {
        var query: [String: Any] = [
            String(kSecClass) : item.rawValue,
            String(kSecMatchLimit) : String(kSecMatchLimitOne),
            String(kSecUseAuthenticationUI) : String(kSecUseAuthenticationUIFail),
            String(kSecReturnPersistentRef): kCFBooleanTrue
        ]
        
        if let accessGroup = self.accessGroup {
            query[String(kSecAttrAccessGroup)] = accessGroup
        }
        
        attributes.forEach { (key, value) in query[key.rawValue] = value }
        
        let result: Result<Data?, KeychainError> = perform(operation: SecItemCopyMatching, query: query)
        
        switch result {
        case .success(let .some(data)): return data
        case .failure(let error): throw error
        default: throw KeychainError.unexpected
        }
    }
    
    func reset() throws {
        let items: [KeychainClass] = [KeychainClass.password, KeychainClass.certificate, KeychainClass.key]
        try items.forEach { item in
            var query: [String: Any] = [
                String(kSecClass) : item.rawValue
            ]
            
            if let accessGroup = self.accessGroup {
                query[String(kSecAttrAccessGroup)] = accessGroup
            }
            
            let result: Result<Data?, KeychainError> = perform(operation: SecItemDelete, query: query)
            if case Result<Data?, KeychainError>.failure(let error) = result, error != .itemNotFound {
                throw error
            }
        }
    }
    
    private func perform<T, O>(operation: O, query: [String : Any], attributes: [String : Any]? = nil) -> Result<T?, KeychainError> {
        var result: AnyObject?
        let status: OSStatus
        
        switch operation {
        case let operation as AddFindOperation:
            status = operation(query as CFDictionary, &result)
        case let operation as DeleteOperation:
            status = operation(query as CFDictionary)
        case let operation as UpdateOperation:
            guard let attributes = attributes else { return Result<T?, KeychainError>.failure(KeychainError.missingValue) }
            status = operation(query as CFDictionary, attributes as CFDictionary)
        default:
            fatalError()
        }
        
        guard status == errSecSuccess else {
            guard let error = KeychainError(rawValue: status) else { fatalError("KeychainError must be defined in either case") }
            return Result<T?, KeychainError>.failure(error)
        }
        
        return Result<T?, KeychainError>.success(result as? T)
    }
    
}
