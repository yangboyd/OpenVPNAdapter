//
//  PacketTunnelProvider.swift
//  OpenVPN Adapter
//
//  Created by Sergey Abramchuk on 05.05.17.
//
//

import NetworkExtension
import OpenVPNAdapter

class PacketTunnelProvider: NEPacketTunnelProvider {

    override func startTunnel(options: [String : NSObject]? = nil, completionHandler: @escaping (Error?) -> Void) {
        
    }
    
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        
    }
    
}

extension PacketTunnelProvider: OpenVPNAdapterDelegate {
    
    func configureTunnel(settings: NEPacketTunnelNetworkSettings, callback: @escaping (OpenVPNAdapterPacketFlow?) -> Void) {
        
    }
    
    func handle(event: OpenVPNEvent, message: String?) {
        
    }
    
    func handle(error: Error) {
        
    }
    
    func handle(logMessage: String) {
        
    }
    
}
