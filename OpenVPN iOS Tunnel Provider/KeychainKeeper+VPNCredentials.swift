//
//  KeychainKeeper+VPNCredentials.swift
//  OpenVPN iOS Tunnel Provider
//
//  Created by Sergey Abramchuk on 17.09.17.
//

import Foundation
import OpenVPNAdapter

extension KeychainKeeper {
    
    func getPrivateKey(with ref: Data, password: String?) throws -> String {
        let derData = (try self.find(item: .key, with: ref)).data
        let privateKey = try OpenVPNPrivateKey(der: derData, password: password)
        
        return try convertToPEM(converter: privateKey)
    }
    
    func getCertificate(with ref: Data) throws -> String {
        let derData = (try self.find(item: .certificate, with: ref)).data
        let certificate = try OpenVPNCertificate(der: derData)
        
        return try convertToPEM(converter: certificate)
    }
    
    func getPassword(with ref: Data) throws -> String {
        let data = (try self.find(item: .password, with: ref)).data
        
        guard let result = String(data: data, encoding: .utf8) else {
            fatalError()
        }
        
        return result
    }
    
    private func convertToPEM(converter: PEMConverter) throws -> String {
        let pemData = try converter.pemData()
        
        guard let result = String(data: pemData, encoding: .utf8)?.replacingOccurrences(of: "\n", with: "\\n") else {
            fatalError()
        }
        
        return result
    }
    
}
