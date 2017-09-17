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
    
    let keychain = KeychainKeeper(accessGroup: nil)
    
    lazy var vpnAdapter: OpenVPNAdapter = {
        return OpenVPNAdapter().then { $0.delegate = self }
    }()
    
    let vpnReachability = OpenVPNReachability()
    
    var startHandler: ((Error?) -> Void)?
    var stopHandler: (() -> Void)?
    
    override func startTunnel(options: [String : NSObject]? = nil, completionHandler: @escaping (Error?) -> Void) {
        guard let protocolConfiguration = protocolConfiguration as? NETunnelProviderProtocol else {
            fatalError("protocolConfiguration should be an instance of the NETunnelProviderProtocol class")
        }
        
        // We need providerConfiguration dictionary to retrieve content of the OpenVPN configuration file.
        // Other options related to the tunnel provider also can be stored there.
        guard let providerConfiguration = protocolConfiguration.providerConfiguration else {
            preconditionFailure("providerConfiguration should be provided to the tunnel provider")
        }
        
        // Retrive vpn configuration, key and certificates from keychain
        guard
            let fileContent = providerConfiguration[ProviderConfigurationKey.fileContent] as? Data,
            let caRef = providerConfiguration[ProviderConfigurationKey.caRef] as? Data,
            let userCertificateRef = providerConfiguration[ProviderConfigurationKey.userCertificateRef] as? Data,
            let userKeyRef = providerConfiguration[ProviderConfigurationKey.userKeyRef] as? Data
        else {
            preconditionFailure("fileContent, certificates and a key should be provided to the tunnel provider")
        }
        
        guard
            let ca = try? retrieveVPNCertificate(ref: caRef),
            let userCertificate = try? retrieveVPNCertificate(ref: userCertificateRef),
            let userKey = try? retrieveVPNKey(ref: userKeyRef, password: nil)
        else {
            fatalError("Failed to retrieve certificates and a user key from keychain")
        }
        
        // Create representation of the OpenVPN configuration. Other properties such as connection timeout or
        // private key password aslo may be provided there.
        let vpnConfiguration = OpenVPNConfiguration().then {
            $0.fileContent = fileContent
            $0.settings = [
                "ca" : ca,
                "cert" : userCertificate,
                "key" : userKey
            ]
        }
        
        // Apply OpenVPN configuration
        let properties: OpenVPNProperties
        do {
            properties = try vpnAdapter.apply(configuration: vpnConfiguration)
        } catch {
            completionHandler(error)
            return
        }
        
        // Provide credentials if needed
        if !properties.autologin {
            guard let username = protocolConfiguration.username else {
                preconditionFailure("username should be provided to the tunnel provider")
            }
            
            guard
                let reference = protocolConfiguration.passwordReference,
                let data = (try? keychain.find(item: .password, with: reference))?.data,
                let password = String(data: data, encoding: .utf8)
            else {
                preconditionFailure("password should be stored in the keychain and the reference should be provided to the tunnel provider")
            }
            
            let credentials = OpenVPNCredentials().then {
                $0.username = username
                $0.password = password
            }
            
            do {
                try vpnAdapter.provide(credentials: credentials)
            } catch {
                completionHandler(error)
                return
            }
        }
        
        // Start checking reachability. In some cases after switching from cellular to WiFi the adapter still uses cellular data.
        // Changing reachability forces reconnection so the adapter will use actual connection.
        vpnReachability.startTracking { [weak self] status in
            guard status != .notReachable else { return }
            self?.vpnAdapter.reconnect(interval: 5)
        }
        
        // Establish connection and wait for .connected event
        startHandler = completionHandler
        vpnAdapter.connect()
    }
    
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        stopHandler = completionHandler
        
        vpnReachability.stopTracking()
        vpnAdapter.disconnect()
    }
    
}

extension PacketTunnelProvider: OpenVPNAdapterDelegate {
    
    func configureTunnel(settings: NEPacketTunnelNetworkSettings, callback: @escaping (OpenVPNAdapterPacketFlow?) -> Void) {
        setTunnelNetworkSettings(settings) { (error) in
            callback(error == nil ? self.packetFlow : nil)
        }
    }
    
    func handle(event: OpenVPNAdapterEvent, message: String?) {
        switch event {
        case .connected:
            if reasserting {
                reasserting = false
            }
            
            guard let startHandler = startHandler else {
                return
            }
            
            startHandler(nil)
            self.startHandler = nil
            
        case .disconnected:
            guard let stopHandler = stopHandler else {
                return
            }
            
            stopHandler()
            self.stopHandler = nil
            
        case .reconnecting:
            reasserting = true
            
        default:
            break
        }
    }
    
    func handle(error: Error) {
        // Handle only fatal errors
        guard let fatal = (error as NSError).userInfo[OpenVPNAdapterErrorFatalKey] as? Bool, fatal == true else {
            return
        }
        
        vpnReachability.stopTracking()
        
        if let startHandler = startHandler {
            startHandler(error)
            self.startHandler = nil
        } else {
            cancelTunnelWithError(error)
        }
    }
    
}

extension PacketTunnelProvider {
    
    func retrieveVPNKey(ref: Data, password: String?) throws -> String {
        let derData = (try keychain.find(item: .key, with: ref)).data
        let privateKey = try OpenVPNPrivateKey(der: derData, password: password)

        return try convertToPEM(converter: privateKey)
    }
    
    func retrieveVPNCertificate(ref: Data) throws -> String {
        let derData = (try keychain.find(item: .certificate, with: ref)).data
        let certificate = try OpenVPNCertificate(der: derData)

        return try convertToPEM(converter: certificate)
    }
    
    func convertToPEM(converter: PEMConverter) throws -> String {
        let pemData = try converter.pemData()
        
        guard let result = String(data: pemData, encoding: .utf8)?.replacingOccurrences(of: "\n", with: "\\n") else {
            fatalError()
        }
        
        return result
    }
    
}
