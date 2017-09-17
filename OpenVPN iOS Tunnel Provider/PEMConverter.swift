//
//  PEMConverter.swift
//  OpenVPN iOS Tunnel Provider
//
//  Created by Sergey Abramchuk on 17.09.17.
//

import Foundation
import OpenVPNAdapter

protocol PEMConverter {
    func pemData() throws -> Data
}

extension OpenVPNCertificate: PEMConverter {}
extension OpenVPNPrivateKey: PEMConverter {}
